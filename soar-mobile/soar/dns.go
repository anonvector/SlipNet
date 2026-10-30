package soar

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// dnsTimeout bounds one query, DoH attempt and DNS-over-TCP fallback together.
	dnsTimeout = 15 * time.Second
	// dohTimeout bounds the DoH attempt, leaving the rest of dnsTimeout for the fallback.
	dohTimeout = 10 * time.Second
	// dnsConnIdle closes a DNS-over-TCP client connection that sends nothing.
	dnsConnIdle = 30 * time.Second
	// dohIdleConn closes an idle DoH connection. An open stream keeps the tunnel polling, so
	// this is kept short, like Soar's own round tripper.
	dohIdleConn = 10 * time.Second

	dnsHeaderLen = 12
	maxDNSMsg    = 65535
)

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// dnsResolver resolves DNS queries through the tunnel: DNS over HTTPS to the
// queried server on port 443, which any soar-server allows, falling back to
// plain DNS over TCP on port 53 for a server that doesn't speak DoH.
type dnsResolver struct {
	dial      dialFunc
	transport *http.Transport
	client    *http.Client

	mu    sync.Mutex
	plain map[string]bool // servers DoH failed on and plain DNS over TCP answered
}

func newDNSResolver(dial dialFunc) *dnsResolver {
	tr := &http.Transport{
		DialContext:         dial,
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     dohIdleConn,
		TLSHandshakeTimeout: dohTimeout,
	}
	return &dnsResolver{
		dial:      dial,
		transport: tr,
		client:    &http.Client{Transport: tr},
		plain:     make(map[string]bool),
	}
}

func (r *dnsResolver) close() {
	r.transport.CloseIdleConnections()
}

// serveTCP answers the DNS-over-TCP queries a client sends on conn as if conn
// were connected to server:53. Queries are resolved concurrently and answered
// as they complete; DNS over TCP matches answers to queries by ID.
func (r *dnsResolver) serveTCP(ctx context.Context, conn net.Conn, server string) error {
	var wmu sync.Mutex
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn.SetReadDeadline(time.Now().Add(dnsConnIdle))
		var l [2]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		q := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(conn, q); err != nil {
			return err
		}
		if len(q) < dnsHeaderLen {
			return fmt.Errorf("dns: short query (%d bytes)", len(q))
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := r.resolve(ctx, server, q)
			if err != nil {
				// Without an answer the client would wait out its own timeout; closing
				// fails its pending queries at once.
				log.Printf("soar: dns via %s: %v", server, err)
				conn.Close()
				return
			}
			out := make([]byte, 2+len(resp))
			binary.BigEndian.PutUint16(out, uint16(len(resp)))
			copy(out[2:], resp)
			wmu.Lock()
			conn.Write(out)
			wmu.Unlock()
		}()
	}
}

// resolve answers one DNS query (wire format, with its ID) addressed to server.
func (r *dnsResolver) resolve(ctx context.Context, server string, q []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()

	r.mu.Lock()
	plain := r.plain[server]
	r.mu.Unlock()
	if plain {
		return r.queryTCP(ctx, server, q)
	}

	dctx, dcancel := context.WithTimeout(ctx, dohTimeout)
	resp, dohErr := r.queryDoH(dctx, server, q)
	dcancel()
	if dohErr == nil {
		return resp, nil
	}
	if ctx.Err() != nil {
		return nil, dohErr
	}
	resp, err := r.queryTCP(ctx, server, q)
	if err != nil {
		return nil, fmt.Errorf("doh: %v; tcp/53: %v", dohErr, err)
	}
	log.Printf("soar: %s does not answer DoH (%v); using DNS over TCP through the tunnel", server, dohErr)
	r.mu.Lock()
	r.plain[server] = true
	r.mu.Unlock()
	return resp, nil
}

// queryDoH sends q to https://server/dns-query (RFC 8484) through the tunnel.
func (r *dnsResolver) queryDoH(ctx context.Context, server string, q []byte) ([]byte, error) {
	msg := append([]byte(nil), q...)
	// RFC 8484 4.1: use ID 0 so responses cache well; the original goes back on the answer.
	id0, id1 := msg[0], msg[1]
	msg[0], msg[1] = 0, 0

	host := server
	if ip := net.ParseIP(server); ip != nil && ip.To4() == nil {
		host = "[" + server + "]"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+"/dns-query", bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMsg+1))
	if err != nil {
		return nil, err
	}
	if len(body) < dnsHeaderLen || len(body) > maxDNSMsg {
		return nil, fmt.Errorf("bad DoH answer length %d", len(body))
	}
	body[0], body[1] = id0, id1
	return body, nil
}

// queryTCP sends q as DNS over TCP to server:53 through the tunnel. The
// server must allow port 53 (soar-server -allow-ports).
func (r *dnsResolver) queryTCP(ctx context.Context, server string, q []byte) ([]byte, error) {
	conn, err := r.dial(ctx, "tcp", net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()

	out := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(out, uint16(len(q)))
	copy(out[2:], q)
	if _, err := conn.Write(out); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if len(resp) < dnsHeaderLen {
		return nil, fmt.Errorf("short answer (%d bytes)", len(resp))
	}
	return resp, nil
}
