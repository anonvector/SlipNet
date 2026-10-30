package soar

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	soarlib "github.com/getlantern/soar"
)

const (
	socksVersion    = 5
	socksCmdConnect = 1

	socksAtypIPv4   = 1
	socksAtypDomain = 3
	socksAtypIPv6   = 4

	socksRepSuccess         = 0
	socksRepFailure         = 1
	socksRepCmdUnsupported  = 7
	socksRepAtypUnsupported = 8

	// handshakeTimeout bounds the SOCKS5 greeting and request.
	handshakeTimeout = 30 * time.Second
)

// handle serves one SOCKS5 client: a CONNECT becomes a Soar stream, or, for
// port 53 with DoH DNS on, a local DNS-over-TCP server.
func (c *SoarClient) handle(ctx context.Context, conn net.Conn, client *soarlib.Client) error {
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	addr, port, err := socksHandshake(conn)
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Time{})

	if port == 53 && c.dohDNS {
		c.mu.Lock()
		dns := c.dns
		c.mu.Unlock()
		if dns == nil {
			return errClosed
		}
		if err := socksReply(conn, socksRepSuccess); err != nil {
			return err
		}
		return dns.serveTCP(ctx, conn, addr)
	}

	target := net.JoinHostPort(addr, strconv.Itoa(port))
	stream, err := client.DialContext(ctx, "tcp", target)
	if err != nil {
		socksReply(conn, socksRepFailure)
		return fmt.Errorf("dial %s: %v", target, err)
	}
	defer stream.Close()
	// The server reports a refused destination as a stream reset, after this
	// reply: answering at once lets the request ride with the stream's opening.
	if err := socksReply(conn, socksRepSuccess); err != nil {
		return err
	}
	return pipe(conn, stream)
}

// socksHandshake reads the greeting and a CONNECT request, and returns the
// requested host (IP literal or name) and port. Username/password auth is
// accepted, with any credentials, for clients that insist on it.
func socksHandshake(conn net.Conn) (string, int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return "", 0, err
	}
	if hdr[0] != socksVersion {
		return "", 0, fmt.Errorf("socks: bad version %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", 0, err
	}
	var noAuth, userPass bool
	for _, m := range methods {
		switch m {
		case 0x00:
			noAuth = true
		case 0x02:
			userPass = true
		}
	}
	switch {
	case noAuth:
		if _, err := conn.Write([]byte{socksVersion, 0x00}); err != nil {
			return "", 0, err
		}
	case userPass:
		if _, err := conn.Write([]byte{socksVersion, 0x02}); err != nil {
			return "", 0, err
		}
		if err := skipUserPass(conn); err != nil {
			return "", 0, err
		}
	default:
		conn.Write([]byte{socksVersion, 0xff})
		return "", 0, errors.New("socks: no acceptable auth method")
	}

	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		return "", 0, err
	}
	if req[0] != socksVersion {
		return "", 0, fmt.Errorf("socks: bad request version %d", req[0])
	}
	var host string
	switch req[3] {
	case socksAtypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(b[:]).String()
	case socksAtypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(b[:]).String()
	case socksAtypDomain:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return "", 0, err
		}
		b := make([]byte, n[0])
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		socksReply(conn, socksRepAtypUnsupported)
		return "", 0, fmt.Errorf("socks: address type %d not supported", req[3])
	}
	var p [2]byte
	if _, err := io.ReadFull(conn, p[:]); err != nil {
		return "", 0, err
	}
	if req[1] != socksCmdConnect {
		socksReply(conn, socksRepCmdUnsupported)
		return "", 0, fmt.Errorf("socks: command %d not supported", req[1])
	}
	return host, int(binary.BigEndian.Uint16(p[:])), nil
}

// skipUserPass reads an RFC 1929 sub-negotiation and accepts it.
func skipUserPass(conn net.Conn) error {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, make([]byte, hdr[1])); err != nil {
		return err
	}
	var n [1]byte
	if _, err := io.ReadFull(conn, n[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, make([]byte, n[0])); err != nil {
		return err
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func socksReply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{socksVersion, rep, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// pipe copies both ways, passing each direction's EOF on as a half-close,
// and returns once both directions are done.
func pipe(local net.Conn, stream net.Conn) error {
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, local)
		closeWrite(stream)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(local, stream)
		closeWrite(local)
		errc <- err
	}()
	err := <-errc
	if err != nil {
		// One side failed: tear both down rather than wait on the other.
		local.Close()
		stream.Close()
		<-errc
		return err
	}
	return <-errc
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}
