package main

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

const maxWorkers = 256

// UDPProxy listens for DNS queries over UDP and forwards to the resolver pool.
type UDPProxy struct {
	listenAddr string
	pool       *ResolverPool
	cache      *DNSCache // nil if disabled
	conn       *net.UDPConn
	queryCount uint64
	done       chan struct{}
}

func NewUDPProxy(addr string, pool *ResolverPool, cache *DNSCache) *UDPProxy {
	return &UDPProxy{
		listenAddr: addr,
		pool:       pool,
		cache:      cache,
		done:       make(chan struct{}),
	}
}

func (u *UDPProxy) Start() error {
	conn, err := u.bindWithRetry()
	if err != nil {
		return err
	}
	u.conn = conn
	slog.Info("UDP proxy listening", "addr", u.listenAddr)

	sem := make(chan struct{}, maxWorkers)
	buf := make([]byte, dnsBufferSize)

	for {
		select {
		case <-u.done:
			return nil
		default:
		}

		u.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-u.done:
				return nil
			default:
			}
			slog.Error("UDP socket error, rebinding...", "err", err)
			u.conn.Close()
			time.Sleep(3 * time.Second)
			conn, err := u.bindWithRetry()
			if err != nil {
				return err
			}
			u.conn = conn
			slog.Info("UDP socket rebound successfully")
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		atomic.AddUint64(&u.queryCount, 1)

		sem <- struct{}{}
		go func(data []byte, addr *net.UDPAddr) {
			defer func() { <-sem }()
			u.forward(data, addr)
		}(data, clientAddr)
	}
}

func (u *UDPProxy) forward(data []byte, clientAddr *net.UDPAddr) {
	// Check cache
	if u.cache != nil {
		if resp, ok := u.cache.Get(data); ok {
			u.conn.WriteToUDP(resp, clientAddr)
			return
		}
	}

	resolver := u.pool.GetNext()
	u.pool.MarkSent(resolver)

	resp, err := u.pool.SendQuery(data, resolver)
	if err != nil {
		u.pool.MarkFailure(resolver)
		slog.Debug("Forward failed", "resolver", resolver, "err", err)

		// Retry with a different resolver
		retry := u.pool.GetNext()
		if retry != resolver {
			u.pool.MarkSent(retry)
			resp, err = u.pool.SendQuery(data, retry)
			if err != nil {
				u.pool.MarkFailure(retry)
				return
			}
			u.pool.MarkSuccess(retry)
		} else {
			return
		}
	} else {
		u.pool.MarkSuccess(resolver)
	}

	if u.cache != nil {
		u.cache.Put(data, resp)
	}
	u.conn.WriteToUDP(resp, clientAddr)
}

func (u *UDPProxy) bindWithRetry() (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", u.listenAddr)
	if err != nil {
		return nil, err
	}
	for {
		select {
		case <-u.done:
			return nil, net.ErrClosed
		default:
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			slog.Warn("UDP bind failed, retrying in 3s...", "addr", u.listenAddr, "err", err)
			time.Sleep(3 * time.Second)
			continue
		}
		return conn, nil
	}
}

func (u *UDPProxy) Stop() {
	close(u.done)
	if u.conn != nil {
		u.conn.Close()
	}
}

func (u *UDPProxy) QueryCount() uint64 {
	return atomic.LoadUint64(&u.queryCount)
}

// TCPProxy listens for DNS queries over TCP with 2-byte length framing.
type TCPProxy struct {
	listenAddr string
	pool       *ResolverPool
	cache      *DNSCache
	listener   net.Listener
	done       chan struct{}
}

func NewTCPProxy(addr string, pool *ResolverPool, cache *DNSCache) *TCPProxy {
	return &TCPProxy{
		listenAddr: addr,
		pool:       pool,
		cache:      cache,
		done:       make(chan struct{}),
	}
}

func (t *TCPProxy) Start() error {
	ln, err := t.bindWithRetry()
	if err != nil {
		return err
	}
	t.listener = ln
	slog.Info("TCP proxy listening", "addr", t.listenAddr)

	sem := make(chan struct{}, maxWorkers)
	for {
		select {
		case <-t.done:
			return nil
		default:
		}

		t.listener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
		conn, err := t.listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-t.done:
				return nil
			default:
			}
			slog.Error("TCP accept error", "err", err)
			return err
		}

		sem <- struct{}{}
		go func(c net.Conn) {
			defer func() { <-sem }()
			t.handle(c)
		}(conn)
	}
}

func (t *TCPProxy) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Read 2-byte length prefix
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return
	}
	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	if msgLen == 0 || msgLen > dnsBufferSize {
		return
	}

	data := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, data); err != nil {
		return
	}

	// Check cache
	if t.cache != nil {
		if resp, ok := t.cache.Get(data); ok {
			var respLen [2]byte
			binary.BigEndian.PutUint16(respLen[:], uint16(len(resp)))
			conn.Write(respLen[:])
			conn.Write(resp)
			return
		}
	}

	resolver := t.pool.GetNext()
	t.pool.MarkSent(resolver)

	resp, err := t.pool.SendQuery(data, resolver)
	if err != nil {
		t.pool.MarkFailure(resolver)
		slog.Debug("TCP forward failed", "resolver", resolver, "err", err)
		return
	}
	t.pool.MarkSuccess(resolver)

	if t.cache != nil {
		t.cache.Put(data, resp)
	}

	var respLen [2]byte
	binary.BigEndian.PutUint16(respLen[:], uint16(len(resp)))
	conn.Write(respLen[:])
	conn.Write(resp)
}

func (t *TCPProxy) bindWithRetry() (net.Listener, error) {
	for {
		select {
		case <-t.done:
			return nil, net.ErrClosed
		default:
		}
		ln, err := net.Listen("tcp", t.listenAddr)
		if err != nil {
			slog.Warn("TCP bind failed, retrying in 3s...", "addr", t.listenAddr, "err", err)
			time.Sleep(3 * time.Second)
			continue
		}
		return ln, nil
	}
}

func (t *TCPProxy) Stop() {
	close(t.done)
	if t.listener != nil {
		t.listener.Close()
	}
}
