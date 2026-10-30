package soar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	soarlib "github.com/getlantern/soar"
)

const testZone = "t.example.com"

// startServer runs a Soar server on loopback that dials destinations with dial, and returns
// its address (the client uses it directly as a resolver) and public key.
func startServer(t *testing.T, dial dialFunc) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go soarlib.Serve(ctx, pc, soarlib.ServerConfig{Zone: testZone, PrivateKey: priv, Dial: dial})
	return pc.LocalAddr().String(), pub
}

func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func startClient(t *testing.T, resolver string, pub ed25519.PublicKey) *SoarClient {
	t.Helper()
	c, err := NewClient(resolver, testZone, base64.StdEncoding.EncodeToString(pub), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Stop)
	return c
}

func (c *SoarClient) addr() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.listener.Addr().String()
}

// socksConnect opens a SOCKS5 CONNECT to host:port through the client.
func socksConnect(t *testing.T, proxy, host string, port int) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	conn.Write([]byte{5, 1, 0})
	var m [2]byte
	if _, err := io.ReadFull(conn, m[:]); err != nil || m != [2]byte{5, 0} {
		t.Fatalf("greeting: %v %v", m, err)
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host).To4(); ip != nil {
		req = append(append(req, 1), ip...)
	} else {
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	conn.Write(req)
	var rep [10]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil || rep[1] != 0 {
		t.Fatalf("connect reply: %v %v", rep, err)
	}
	return conn
}

func TestSocksConnectThroughTunnel(t *testing.T) {
	echo := startEcho(t)
	server, pub := startServer(t, (&net.Dialer{}).DialContext)
	c := startClient(t, server, pub)

	host, port, _ := net.SplitHostPort(echo)
	p, _ := strconv.Atoi(port)
	conn := socksConnect(t, c.addr(), host, p)
	defer conn.Close()

	msg := bytes.Repeat([]byte("soar"), 4096)
	go conn.Write(msg)
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("echo mismatch")
	}
	if !c.IsEstablished() {
		t.Error("IsEstablished = false after a stream carried data")
	}
	if c.VerifiedPathCount() != 1 {
		t.Errorf("VerifiedPathCount = %d, want 1", c.VerifiedPathCount())
	}
}

// startDNSOverTCP serves DNS over TCP, answering every query with its own bytes and QR set.
func startDNSOverTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					var l [2]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(l[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					q[2] |= 0x80
					c.Write(append(l[:], q...))
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// TestDNSFallsBackToTCP: a DNS server that doesn't speak DoH is reached with plain DNS over
// TCP through the tunnel, and the client remembers that.
func TestDNSFallsBackToTCP(t *testing.T) {
	dnsAddr := startDNSOverTCP(t)
	// The server sends every :53 stream to the fake DNS server and refuses :443, as a
	// resolver without DoH would.
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, _ := net.SplitHostPort(addr)
		if port != "53" {
			return nil, fmt.Errorf("refused %s", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, dnsAddr)
	}
	server, pub := startServer(t, dial)
	c := startClient(t, server, pub)

	conn := socksConnect(t, c.addr(), "192.0.2.1", 53)
	defer conn.Close()
	q, _ := hex.DecodeString("abcd01000001000000000000076578616d706c6503636f6d0000010001")
	conn.Write(binary.BigEndian.AppendUint16(nil, uint16(len(q))))
	conn.Write(q)
	var l [2]byte
	if _, err := io.ReadFull(conn, l[:]); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0xab || resp[1] != 0xcd || resp[2]&0x80 == 0 || !bytes.Equal(resp[3:], q[3:]) {
		t.Fatalf("bad answer %x", resp)
	}
	c.mu.Lock()
	plain := c.dns.plain["192.0.2.1"]
	c.mu.Unlock()
	if !plain {
		t.Error("server not remembered as plain DNS")
	}
}

func TestStopClosesListener(t *testing.T) {
	server, pub := startServer(t, (&net.Dialer{}).DialContext)
	c := startClient(t, server, pub)
	addr := c.addr()
	if !c.IsRunning() {
		t.Fatal("not running after Start")
	}
	c.Stop()
	if c.IsRunning() {
		t.Error("running after Stop")
	}
	if conn, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		conn.Close()
		t.Error("listener still accepting after Stop")
	}
}

func TestDecodePublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, s := range []string{
		base64.StdEncoding.EncodeToString(pub),
		base64.RawStdEncoding.EncodeToString(pub),
		base64.URLEncoding.EncodeToString(pub),
		hex.EncodeToString(pub),
		" " + base64.StdEncoding.EncodeToString(pub) + "\n",
	} {
		got, err := decodePublicKey(s)
		if err != nil || !bytes.Equal(got, pub) {
			t.Errorf("decodePublicKey(%q) = %x, %v", s, got, err)
		}
	}
	for _, s := range []string{"", "abc", base64.StdEncoding.EncodeToString(pub[:31])} {
		if _, err := decodePublicKey(s); err == nil {
			t.Errorf("decodePublicKey(%q) succeeded", s)
		}
	}
}

func TestNewClientResolvers(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	c, err := NewClient(" 8.8.8.8 ,tcp://1.1.1.1:5353,[2001:db8::1],9.9.9.9:53,", testZone+".", hex.EncodeToString(pub), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"8.8.8.8:53", "1.1.1.1:5353", "[2001:db8::1]:53", "9.9.9.9:53"}
	if fmt.Sprint(c.resolvers) != fmt.Sprint(want) {
		t.Errorf("resolvers = %v, want %v", c.resolvers, want)
	}
	if !c.streamOnly["1.1.1.1:5353"] || len(c.streamOnly) != 1 {
		t.Errorf("streamOnly = %v", c.streamOnly)
	}
	if c.zone != testZone {
		t.Errorf("zone = %q", c.zone)
	}
}

// TestSocksHandshakeMethods: JSch (SSH over Soar) offers no-auth and user/pass together; some
// clients offer only user/pass. Both must reach the CONNECT, here by domain name.
func TestSocksHandshakeMethods(t *testing.T) {
	for _, tc := range []struct {
		name     string
		greeting []byte
		auth     []byte // sub-negotiation the client sends after the method reply
		method   byte
	}{
		{"noauth+userpass", []byte{5, 2, 0, 2}, nil, 0},
		{"userpass only", []byte{5, 1, 2}, []byte{1, 1, 'u', 1, 'p'}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			type result struct {
				host string
				port int
				err  error
			}
			done := make(chan result, 1)
			go func() {
				h, p, err := socksHandshake(server)
				done <- result{h, p, err}
			}()
			client.SetDeadline(time.Now().Add(5 * time.Second))
			client.Write(tc.greeting)
			var m [2]byte
			if _, err := io.ReadFull(client, m[:]); err != nil || m != [2]byte{5, tc.method} {
				t.Fatalf("method reply %v, %v", m, err)
			}
			if tc.auth != nil {
				client.Write(tc.auth)
				var a [2]byte
				if _, err := io.ReadFull(client, a[:]); err != nil || a != [2]byte{1, 0} {
					t.Fatalf("auth reply %v, %v", a, err)
				}
			}
			req := append([]byte{5, 1, 0, 3, 9}, "127.0.0.1"...)
			client.Write(binary.BigEndian.AppendUint16(req, 22))
			r := <-done
			if r.err != nil || r.host != "127.0.0.1" || r.port != 22 {
				t.Fatalf("handshake = %q:%d, %v", r.host, r.port, r.err)
			}
		})
	}
}

// startTCPResolver serves DNS over TCP by relaying each query to the UDP server, as a recursive
// resolver reached over TCP/53 would.
func startTCPResolver(t *testing.T, server string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				up, err := net.Dial("udp", server)
				if err != nil {
					return
				}
				defer up.Close()
				go func() {
					buf := make([]byte, 65535)
					for {
						n, err := up.Read(buf)
						if err != nil {
							return
						}
						c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(n)), buf[:n]...))
					}
				}()
				for {
					var l [2]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(l[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					up.Write(q)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// startSocksProxy runs a plain SOCKS5 proxy and reports each CONNECT target on the channel.
func startSocksProxy(t *testing.T) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	targets := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				host, port, err := socksHandshake(c)
				if err != nil {
					return
				}
				target := net.JoinHostPort(host, strconv.Itoa(port))
				select {
				case targets <- target:
				default:
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					socksReply(c, socksRepFailure)
					return
				}
				defer up.Close()
				socksReply(c, socksRepSuccess)
				pipe(c, up)
			}()
		}
	}()
	return ln.Addr().String(), targets
}

// TestUpstreamSocks5: behind a previous chain layer, resolver traffic rides that layer's SOCKS5
// as DNS over TCP, and streams still reach their destination.
func TestUpstreamSocks5(t *testing.T) {
	echo := startEcho(t)
	server, pub := startServer(t, (&net.Dialer{}).DialContext)
	resolver := startTCPResolver(t, server)
	socksAddr, targets := startSocksProxy(t)

	c, err := NewClient(resolver, testZone, base64.StdEncoding.EncodeToString(pub), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.SetUpstreamSocks5(socksAddr, "", "")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Stop)

	host, port, _ := net.SplitHostPort(echo)
	p, _ := strconv.Atoi(port)
	conn := socksConnect(t, c.addr(), host, p)
	defer conn.Close()
	msg := []byte("through the chain")
	conn.Write(msg)
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo %q", got)
	}
	select {
	case target := <-targets:
		if target != resolver {
			t.Errorf("upstream proxy reached %s, want the resolver %s", target, resolver)
		}
	default:
		t.Error("resolver traffic did not go through the upstream SOCKS5 proxy")
	}
	for _, ps := range c.client.PathStats() {
		if ps.Transport != "tcp" {
			t.Errorf("path %s uses %s, want tcp only", ps.Resolver, ps.Transport)
		}
	}
}
