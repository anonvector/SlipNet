// Package snowflake provides a gomobile-compatible API for the Snowflake
// pluggable transport client.
//
// Snowflake routes traffic through the Tor network using WebRTC volunteer
// proxies. It runs a local SOCKS5 server that Tor connects through.
//
// Multi-CDN fallback: if the broker on one CDN becomes unreachable (e.g.
// blocked by censors), the client automatically rotates to the next CDN.
package snowflake

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	sflib "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/client/lib"
)

// maxDialFailures is the number of consecutive Dial() failures before
// rotating to the next CDN configuration.
const maxDialFailures = 5

// cdnConfig holds a broker URL and its matching front domains.
// If ampCacheURL is set, AMP cache rendezvous is used instead of domain fronting.
type cdnConfig struct {
	brokerURL    string
	frontDomains []string
	ampCacheURL  string // optional; uses AMP cache rendezvous when non-empty
}

// builtinCDNs are the CDN configurations to try, ordered by preference.
// These match the latest Tor Browser defaults.
var builtinCDNs = []cdnConfig{
	{
		brokerURL:    "https://1098762253.rsc.cdn77.org/",
		frontDomains: []string{"www.cdn77.com"},
	},
	{
		// AMP cache rendezvous: routes broker requests through Google's AMP CDN.
		// Very hard to block without blocking all of Google — best fallback for Iran.
		brokerURL:    "https://snowflake-broker.torproject.net/",
		ampCacheURL:  "https://cdn.ampproject.org/",
		frontDomains: []string{"www.google.com"},
	},
	{
		brokerURL:    "https://snowflake-broker.torproject.net.global.prod.fastly.net/",
		frontDomains: []string{"www.shazam.com", "www.cosmopolitan.com", "www.esquire.com"},
	},
	{
		brokerURL:    "https://snowflake-broker.azureedge.net/",
		frontDomains: []string{"ajax.aspnetcdn.com"},
	},
}

const (
	// Diverse STUN servers — avoids Google (blocked in Iran).
	// Includes port 443 and 10000 variants (harder to block than 3478).
	defaultSTUNURLs = "" +
		"stun:stun.antisip.com:3478," +
		"stun:stun.epygi.com:3478," +
		"stun:stun.uls.co.za:3478," +
		"stun:stun.voipgate.com:3478," +
		"stun:stun.mixvoip.com:3478," +
		"stun:stun.nextcloud.com:3478," +
		"stun:stun.bethesda.net:3478," +
		"stun:stun.nextcloud.com:443," +
		"stun:stun.sipgate.net:3478," +
		"stun:stun.sipgate.net:10000," +
		"stun:stun.sonetel.com:3478," +
		"stun:stun.voipia.net:3478," +
		"stun:stun.ucsb.edu:3478," +
		"stun:stun.schlund.de:3478"
	defaultUTLSClientID = "hellorandomizedalpn"
)

// SnowflakeClient wraps the Snowflake pluggable transport with Start/Stop lifecycle
// and automatic CDN fallback.
type SnowflakeClient struct {
	listenAddr   string
	cdnConfigs   []cdnConfig
	iceAddresses []string
	utlsClientID string

	mu       sync.Mutex
	running  bool
	cancel   context.CancelFunc
	listener net.Listener

	// Transport management with CDN rotation.
	transportMu  sync.Mutex
	transport    *sflib.Transport
	cdnIndex     int
	dialFailures int32 // atomic; consecutive failures
}

// NewClient creates a new Snowflake PT client with multi-CDN fallback.
// brokerURL and frontDomains set the primary CDN (tried first).
// Pass empty strings to use defaults. Built-in fallback CDNs are added
// automatically.
// frontDomains and stunURLs are comma-separated lists.
func NewClient(listenAddr, brokerURL, frontDomains, stunURLs, utlsClientID, ampCacheURL string) (*SnowflakeClient, error) {
	if listenAddr == "" {
		return nil, fmt.Errorf("listen address is required")
	}
	if stunURLs == "" {
		stunURLs = defaultSTUNURLs
	}
	if utlsClientID == "" {
		utlsClientID = defaultUTLSClientID
	}

	// Build CDN config list: primary (from params) + built-in fallbacks.
	var cdnConfigs []cdnConfig
	if brokerURL != "" && frontDomains != "" {
		cdnConfigs = append(cdnConfigs, cdnConfig{
			brokerURL:    brokerURL,
			frontDomains: splitTrimmed(frontDomains),
			ampCacheURL:  ampCacheURL,
		})
	}
	for _, fb := range builtinCDNs {
		// Skip builtin if it matches the primary (same broker + same AMP cache method).
		if fb.brokerURL == brokerURL && fb.ampCacheURL == ampCacheURL {
			continue
		}
		cdnConfigs = append(cdnConfigs, fb)
	}
	// Safety: if nothing was configured, use all built-ins.
	if len(cdnConfigs) == 0 {
		cdnConfigs = builtinCDNs
	}

	return &SnowflakeClient{
		listenAddr:   listenAddr,
		cdnConfigs:   cdnConfigs,
		iceAddresses: splitTrimmed(stunURLs),
		utlsClientID: utlsClientID,
	}, nil
}

// Start begins the Snowflake PT SOCKS5 server in a background goroutine.
func (c *SnowflakeClient) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("client is already running")
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel

	ln, err := net.Listen("tcp", c.listenAddr)
	if err != nil {
		cancel()
		return fmt.Errorf("opening listener on %s: %v", c.listenAddr, err)
	}
	c.listener = ln
	c.running = true

	// Close listener when context is canceled.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	// Create initial transport, trying each CDN config until one works.
	var transport *sflib.Transport
	var lastErr error
	for i := range c.cdnConfigs {
		transport, lastErr = c.createTransport(i)
		if lastErr == nil {
			c.cdnIndex = i
			break
		}
		log.Printf("Snowflake: CDN %d/%d failed to init: %v, trying next...",
			i+1, len(c.cdnConfigs), lastErr)
	}
	if transport == nil {
		ln.Close()
		cancel()
		c.running = false
		return fmt.Errorf("all CDN configs failed, last error: %v", lastErr)
	}
	c.transport = transport

	go func() {
		defer func() {
			c.mu.Lock()
			c.running = false
			c.mu.Unlock()
		}()

		err := c.run(ctx, ln)
		if err != nil && ctx.Err() == nil {
			log.Printf("snowflake client: %v", err)
		}
	}()

	return nil
}

// createTransport builds a Snowflake transport for the given CDN index.
func (c *SnowflakeClient) createTransport(idx int) (*sflib.Transport, error) {
	cdn := c.cdnConfigs[idx]
	config := sflib.ClientConfig{
		BrokerURL:     cdn.brokerURL,
		AmpCacheURL:   cdn.ampCacheURL,
		FrontDomains:  cdn.frontDomains,
		ICEAddresses:  c.iceAddresses,
		Max:           3,
		UTLSClientID:  c.utlsClientID,
		UTLSRemoveSNI: true,
	}
	if cdn.ampCacheURL != "" {
		log.Printf("Snowflake: using CDN %d/%d — AMP cache=%s broker=%s fronts=%v",
			idx+1, len(c.cdnConfigs), cdn.ampCacheURL, cdn.brokerURL, cdn.frontDomains)
	} else {
		log.Printf("Snowflake: using CDN %d/%d — broker=%s fronts=%v",
			idx+1, len(c.cdnConfigs), cdn.brokerURL, cdn.frontDomains)
	}
	return sflib.NewSnowflakeClient(config)
}

// rotateCDN switches to the next CDN configuration.
// Called when consecutive dial failures exceed the threshold.
func (c *SnowflakeClient) rotateCDN() {
	c.transportMu.Lock()
	defer c.transportMu.Unlock()

	nextIdx := (c.cdnIndex + 1) % len(c.cdnConfigs)
	log.Printf("Snowflake: CDN %d failed after %d attempts, rotating to CDN %d/%d",
		c.cdnIndex+1, maxDialFailures, nextIdx+1, len(c.cdnConfigs))

	transport, err := c.createTransport(nextIdx)
	if err != nil {
		log.Printf("Snowflake: failed to create transport for CDN %d: %v", nextIdx+1, err)
		return
	}

	c.transport = transport
	c.cdnIndex = nextIdx
	atomic.StoreInt32(&c.dialFailures, 0)
}

// getTransport returns the current transport (thread-safe).
func (c *SnowflakeClient) getTransport() *sflib.Transport {
	c.transportMu.Lock()
	defer c.transportMu.Unlock()
	return c.transport
}

// Stop shuts down the Snowflake PT.
func (c *SnowflakeClient) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.listener != nil {
		c.listener.Close()
		c.listener = nil
	}
	c.running = false
}

// IsRunning returns whether the client is currently running.
func (c *SnowflakeClient) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// run accepts connections on the local listener and proxies each through
// Snowflake's WebRTC transport.
func (c *SnowflakeClient) run(ctx context.Context, ln net.Listener) error {
	for {
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // Shutdown requested.
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			return err
		}
		go func() {
			defer local.Close()
			if err := c.handle(ctx, local); err != nil {
				log.Printf("snowflake handle: %v", err)
			}
		}()
	}
}

// handle proxies a single connection through Snowflake.
// Tor connects via SOCKS5 (ClientTransportPlugin ... socks5), so we must
// complete the SOCKS5 handshake before proxying raw data through WebRTC.
func (c *SnowflakeClient) handle(ctx context.Context, local net.Conn) error {
	// --- SOCKS5 handshake (RFC 1928) ---
	// 1. Greeting: client sends [VER, NMETHODS, METHODS...]
	buf := make([]byte, 256)
	if _, err := io.ReadFull(local, buf[:2]); err != nil {
		return fmt.Errorf("socks5 greeting: %v", err)
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("socks5: unsupported version %d", buf[0])
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(local, buf[:nMethods]); err != nil {
		return fmt.Errorf("socks5 methods: %v", err)
	}
	// Reply: no authentication required (method 0x00)
	if _, err := local.Write([]byte{0x05, 0x00}); err != nil {
		return fmt.Errorf("socks5 greeting reply: %v", err)
	}

	// 2. Connect request: [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
	if _, err := io.ReadFull(local, buf[:4]); err != nil {
		return fmt.Errorf("socks5 request header: %v", err)
	}
	// Skip the destination address — Snowflake always connects to the bridge.
	atyp := buf[3]
	switch atyp {
	case 0x01: // IPv4: 4 bytes + 2 port
		if _, err := io.ReadFull(local, buf[:6]); err != nil {
			return fmt.Errorf("socks5 ipv4 addr: %v", err)
		}
	case 0x03: // Domain: 1 len + domain + 2 port
		if _, err := io.ReadFull(local, buf[:1]); err != nil {
			return fmt.Errorf("socks5 domain len: %v", err)
		}
		domLen := int(buf[0])
		if _, err := io.ReadFull(local, buf[:domLen+2]); err != nil {
			return fmt.Errorf("socks5 domain addr: %v", err)
		}
	case 0x04: // IPv6: 16 bytes + 2 port
		if _, err := io.ReadFull(local, buf[:18]); err != nil {
			return fmt.Errorf("socks5 ipv6 addr: %v", err)
		}
	default:
		return fmt.Errorf("socks5: unsupported address type %d", atyp)
	}

	// Reply: success (bound address 0.0.0.0:0)
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := local.Write(reply); err != nil {
		return fmt.Errorf("socks5 connect reply: %v", err)
	}

	// --- Proxy raw data through Snowflake WebRTC ---
	transport := c.getTransport()
	remote, err := transport.Dial()
	if err != nil {
		// Track consecutive failures for CDN rotation.
		failures := atomic.AddInt32(&c.dialFailures, 1)
		if failures >= maxDialFailures {
			c.rotateCDN()
		}
		return fmt.Errorf("snowflake dial: %v", err)
	}
	// Reset failure counter on success.
	atomic.StoreInt32(&c.dialFailures, 0)
	defer remote.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(remote, local)
	}()
	go func() {
		defer wg.Done()
		io.Copy(local, remote)
	}()
	wg.Wait()
	return nil
}

// splitTrimmed splits a comma-separated string into a trimmed slice,
// filtering out empty entries.
func splitTrimmed(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
