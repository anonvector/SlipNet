// Package soar provides a gomobile-compatible API for the Soar DNS tunnel
// client (github.com/getlantern/soar).
//
// Soar carries TCP streams through every configured recursive resolver at
// once to a server that is the authoritative name server for the tunnel zone.
// The server dials each stream's destination itself, so the client exposes a
// local SOCKS5 server (CONNECT only): each CONNECT becomes one Soar stream.
//
// A CONNECT to port 53 is answered locally instead of being tunnelled as-is:
// the DNS-over-TCP queries it carries are resolved with DNS over HTTPS to the
// same address through the tunnel. A stock soar-server only lets streams
// reach ports 80 and 443, so plain DNS to port 53 would be refused.
package soar

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	soarlib "github.com/getlantern/soar"
	"golang.org/x/net/proxy"
)

// warmupTimeout bounds the background handshake started by Start.
const warmupTimeout = 30 * time.Second

// SoarClient wraps a Soar tunnel client with a Start/Stop lifecycle and a
// local SOCKS5 front.
type SoarClient struct {
	resolvers  []string
	streamOnly map[string]bool
	zone       string
	serverKey  ed25519.PublicKey
	listenAddr string

	// discovery finds more resolvers that carry the tunnel, vetted by the
	// tunnel's own authenticated handshake.
	discovery bool
	// country is the ISO 3166-1 alpha-2 code selecting Soar's bundled
	// in-country resolver lists (e.g. "IR"). Empty = global list only.
	country string
	// tcpMode controls TCP/53 paths: "auto" (default), "on", "only", "off".
	tcpMode string
	// safeQName is the query-name length every path starts at. 0 = Soar's
	// default (101).
	safeQName int
	// dohDNS answers port-53 CONNECTs locally with DNS over HTTPS through
	// the tunnel. Default true.
	dohDNS  bool
	verbose bool
	// upstream is a SOCKS5 proxy (host:port) that resolver traffic goes
	// through, as DNS over TCP. Empty = resolvers are reached directly.
	upstream, upstreamUser, upstreamPass string

	mu       sync.Mutex
	running  bool
	client   *soarlib.Client
	listener net.Listener
	dns      *dnsResolver
	conns    map[net.Conn]struct{}
	cancel   context.CancelFunc
}

// NewClient creates a new Soar client.
//
// resolvers is a comma-separated list of recursive resolvers ("host:port",
// or "host" for port 53). A "tcp://" prefix marks a resolver that only
// speaks DNS over TCP. May be empty when discovery is enabled.
// publicKey is the server's Ed25519 public key, as printed by
// `soar-server pubkey` (base64), or hex.
func NewClient(resolvers, zone, publicKey, listenAddr string) (*SoarClient, error) {
	zone = strings.TrimSuffix(strings.TrimSpace(zone), ".")
	if zone == "" {
		return nil, fmt.Errorf("tunnel domain is required")
	}
	if listenAddr == "" {
		return nil, fmt.Errorf("listen address is required")
	}
	key, err := decodePublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	c := &SoarClient{
		zone:       zone,
		serverKey:  key,
		listenAddr: listenAddr,
		streamOnly: make(map[string]bool),
		tcpMode:    "auto",
		dohDNS:     true,
	}
	for _, r := range strings.Split(resolvers, ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		tcpOnly := false
		if rest, ok := strings.CutPrefix(r, "tcp://"); ok {
			r, tcpOnly = rest, true
		}
		if _, _, err := net.SplitHostPort(r); err != nil {
			r = net.JoinHostPort(strings.Trim(r, "[]"), "53")
		}
		c.resolvers = append(c.resolvers, r)
		if tcpOnly {
			c.streamOnly[r] = true
		}
	}
	return c, nil
}

// decodePublicKey parses a server public key given as base64 (standard or
// URL alphabet, padded or not) or hex.
func decodePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("public key is required")
	}
	if len(s) == 2*ed25519.PublicKeySize {
		if b, err := hex.DecodeString(s); err == nil {
			return ed25519.PublicKey(b), nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, fmt.Errorf("invalid public key: want a base64 or hex %d-byte Ed25519 key", ed25519.PublicKeySize)
}

// SetDiscovery enables or disables resolver discovery. country selects
// Soar's bundled in-country resolver lists ("IR", "RU", "CN"); empty uses
// the global list only. Must be called before Start.
func (c *SoarClient) SetDiscovery(enabled bool, country string) {
	c.discovery = enabled
	c.country = strings.TrimSpace(country)
}

// SetTCPMode controls TCP/53 paths: "auto" (default) adds one for a resolver
// whose UDP path never answers, "on" adds one for every resolver, "only"
// uses TCP alone, "off" never. Must be called before Start.
func (c *SoarClient) SetTCPMode(mode string) {
	switch mode {
	case "on", "only", "off":
		c.tcpMode = mode
	default:
		c.tcpMode = "auto"
	}
}

// SetSafeQName sets the query-name length every path starts at; paths probe
// longer names from there. 0 = default (101). Must be called before Start.
func (c *SoarClient) SetSafeQName(n int) {
	c.safeQName = n
}

// SetDoHDns enables or disables answering port-53 CONNECTs locally with DNS
// over HTTPS through the tunnel (default on). When off, they are tunnelled
// as plain DNS over TCP, which the server must allow (-allow-ports).
// Must be called before Start.
func (c *SoarClient) SetDoHDns(enabled bool) {
	c.dohDNS = enabled
}

// SetVerbose enables Soar's debug logging. Must be called before Start.
func (c *SoarClient) SetVerbose(enabled bool) {
	c.verbose = enabled
}

// SetUpstreamSocks5 sends resolver traffic through a SOCKS5 proxy (a
// previous layer of a proxy chain). A CONNECT-only proxy can't carry UDP, so
// every resolver path becomes DNS over TCP (TCP/53) through it, whatever
// SetTCPMode says. user and pass may be empty. Empty addr = direct.
// Must be called before Start.
func (c *SoarClient) SetUpstreamSocks5(addr, user, pass string) {
	c.upstream, c.upstreamUser, c.upstreamPass = addr, user, pass
}

// Start creates the tunnel client and begins serving SOCKS5 on the listen
// address. The tunnel handshakes in the background.
func (c *SoarClient) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("client is already running")
	}

	level := slog.LevelInfo
	if c.verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg := soarlib.Config{
		Zone:      c.zone,
		ServerKey: c.serverKey,
		Resolvers: c.resolvers,
		Discovery: soarlib.Discovery{Enabled: c.discovery, Country: c.country},
		SafeQName: c.safeQName,
		TCP:       c.tcpMode,
		Logger:    logger,
	}
	if len(c.streamOnly) > 0 {
		streamOnly := c.streamOnly
		cfg.StreamOnly = func(r string) bool { return streamOnly[r] }
	}
	if c.upstream != "" {
		var auth *proxy.Auth
		if c.upstreamUser != "" {
			auth = &proxy.Auth{User: c.upstreamUser, Password: c.upstreamPass}
		}
		d, err := proxy.SOCKS5("tcp", c.upstream, auth, proxy.Direct)
		if err != nil {
			return fmt.Errorf("upstream SOCKS5 %s: %v", c.upstream, err)
		}
		cfg.DialTCP = d.(proxy.ContextDialer).DialContext
		cfg.TCP = "only"
	}

	client, err := soarlib.NewClient(cfg)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", c.listenAddr)
	if err != nil {
		client.Close()
		return fmt.Errorf("listen %s: %v", c.listenAddr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.client = client
	c.listener = ln
	c.cancel = cancel
	c.conns = make(map[net.Conn]struct{})
	c.dns = newDNSResolver(client.DialContext)
	c.running = true

	log.Printf("soar: %d resolvers, discovery=%v country=%q tcp=%s, listening on %s",
		len(c.resolvers), c.discovery, c.country, cfg.TCP, ln.Addr())
	if c.upstream != "" {
		log.Printf("soar: resolver traffic goes through SOCKS5 %s (DNS over TCP)", c.upstream)
	}

	go c.serve(ctx, ln, client)
	go c.warmup(ctx, client)
	return nil
}

// warmup handshakes with the server so the first stream doesn't wait for it,
// and logs whether the tunnel came up.
func (c *SoarClient) warmup(ctx context.Context, client *soarlib.Client) {
	ctx, cancel := context.WithTimeout(ctx, warmupTimeout)
	defer cancel()
	start := time.Now()
	rt, err := client.NewRoundTripper(ctx, "")
	if err != nil {
		if ctx.Err() == context.Canceled {
			return
		}
		log.Printf("soar: handshake not complete after %v: %v (check the zone, public key and resolvers)",
			time.Since(start).Round(time.Millisecond), err)
		return
	}
	if cl, ok := rt.(interface{ Close() error }); ok {
		cl.Close()
	}
	log.Printf("soar: session established in %v", time.Since(start).Round(time.Millisecond))
}

func (c *SoarClient) serve(ctx context.Context, ln net.Listener, client *soarlib.Client) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("soar: accept: %v", err)
			}
			c.mu.Lock()
			if c.listener == ln {
				c.running = false
			}
			c.mu.Unlock()
			return
		}
		if !c.track(conn) {
			conn.Close()
			return
		}
		go func() {
			defer c.untrack(conn)
			defer conn.Close()
			if err := c.handle(ctx, conn, client); err != nil && ctx.Err() == nil && c.verbose {
				log.Printf("soar: %v", err)
			}
		}()
	}
}

func (c *SoarClient) track(conn net.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conns == nil {
		return false
	}
	c.conns[conn] = struct{}{}
	return true
}

func (c *SoarClient) untrack(conn net.Conn) {
	c.mu.Lock()
	delete(c.conns, conn)
	c.mu.Unlock()
}

// Stop shuts down the SOCKS5 listener, every open stream and the tunnel.
func (c *SoarClient) Stop() {
	c.mu.Lock()
	cancel, ln, client, dns, conns := c.cancel, c.listener, c.client, c.dns, c.conns
	c.cancel, c.listener, c.client, c.dns, c.conns = nil, nil, nil, nil, nil
	c.running = false
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if ln != nil {
		ln.Close()
	}
	for conn := range conns {
		conn.Close()
	}
	if dns != nil {
		dns.close()
	}
	if client != nil {
		client.Close()
	}
}

// IsRunning returns whether the client is serving SOCKS5.
func (c *SoarClient) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// IsEstablished reports whether a session with the server is up. An idle
// client retires its session and handshakes again on the next stream, so
// false does not by itself mean the tunnel is broken.
func (c *SoarClient) IsEstablished() bool {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	return client != nil && client.Established()
}

// PathStatsJSON returns a JSON array describing every resolver path, for
// diagnostics. Empty array when not running.
func (c *SoarClient) PathStatsJSON() string {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil {
		return "[]"
	}
	b, err := json.Marshal(client.PathStats())
	if err != nil {
		return "[]"
	}
	return string(b)
}

// VerifiedPathCount returns how many resolver paths have carried an
// authenticated answer from the server.
func (c *SoarClient) VerifiedPathCount() int {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil {
		return 0
	}
	n := 0
	for _, p := range client.PathStats() {
		if p.Verified {
			n++
		}
	}
	return n
}

var errClosed = errors.New("soar client stopped")
