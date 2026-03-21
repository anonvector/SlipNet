package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"noizdns/mobile"

	"golang.org/x/net/proxy"
)

const e2eTestURL = "http://www.gstatic.com/generate_204"

// E2EResult holds the result of an end-to-end tunnel test.
type E2EResult struct {
	Host         string
	Success      bool
	TunnelMs     int64
	HTTPMs       int64
	TotalMs      int64
	HTTPStatus   int
	Error        string
}

// E2EConfig holds configuration for E2E testing.
type E2EConfig struct {
	TunnelDomain string
	PublicKey    string
	NoizMode     bool
	SSHMode      bool // true for dnstt_ssh/sayedns_ssh — tunnel carries raw SSH, not SOCKS5
	TimeoutMs    int
	Concurrency  int // max parallel E2E tests (bridges are NOT singletons in Go)
	QuerySize    int // max DNS query payload size (0 = full capacity)
	SOCKSUser    string
	SOCKSPass    string
}

// RunE2ETests runs end-to-end tunnel tests on a list of resolver IPs.
// Each test starts a real tunnel through the resolver and makes an HTTP request.
func RunE2ETests(resolvers []string, config E2EConfig, onResult func(E2EResult)) {
	sem := make(chan struct{}, config.Concurrency)
	var wg sync.WaitGroup

	// Each test needs a unique local port
	var portCounter int32 = 19000

	for _, ip := range resolvers {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Find a free port
			port := allocatePort(&portCounter)
			if port == 0 {
				onResult(E2EResult{Host: host, Error: "no free port"})
				return
			}

			result := testResolverE2E(host, port, config)
			onResult(result)
		}(ip)
	}
	wg.Wait()
}

func allocatePort(counter *int32) int {
	// Try ports starting from counter value
	for i := 0; i < 100; i++ {
		p := int(atomic.AddInt32(counter, 1) - 1)
		addr := fmt.Sprintf("127.0.0.1:%d", p)
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return p
		}
	}
	return 0
}

func testResolverE2E(resolverIP string, localPort int, config E2EConfig) E2EResult {
	result := E2EResult{Host: resolverIP}
	listenAddr := fmt.Sprintf("127.0.0.1:%d", localPort)
	dnsAddr := resolverIP + ":53"

	totalStart := time.Now()

	// Phase 1: Start tunnel
	tunnelStart := time.Now()
	client, err := mobile.NewClient(dnsAddr, config.TunnelDomain, config.PublicKey, listenAddr)
	if err != nil {
		result.Error = fmt.Sprintf("create client: %v", err)
		result.TotalMs = time.Since(totalStart).Milliseconds()
		return result
	}

	client.SetAuthoritativeMode(false)
	if config.NoizMode {
		client.SetNoizMode(true)
	}
	if config.QuerySize > 0 {
		client.SetMaxPayload(config.QuerySize)
	}
	if config.SOCKSUser != "" {
		client.SetSocksCredentials(config.SOCKSUser, config.SOCKSPass)
	}

	if err := client.Start(); err != nil {
		result.Error = fmt.Sprintf("start tunnel: %v", err)
		result.TotalMs = time.Since(totalStart).Milliseconds()
		return result
	}
	defer client.Stop()

	// Wait for tunnel port to be ready
	if !waitForPort(listenAddr, 5*time.Second) {
		result.Error = "tunnel port not ready"
		result.TotalMs = time.Since(totalStart).Milliseconds()
		return result
	}

	result.TunnelMs = time.Since(tunnelStart).Milliseconds()

	// Phase 2: Verify tunnel — SSH banner check or HTTP through SOCKS5
	if config.SSHMode {
		// SSH variant: tunnel forwards raw TCP to SSH server.
		// Read the SSH banner to prove bidirectional data flow.
		sshStart := time.Now()
		conn, err := net.DialTimeout("tcp", listenAddr, 5*time.Second)
		if err != nil {
			result.Error = fmt.Sprintf("ssh connect: %v", err)
			result.TotalMs = time.Since(totalStart).Milliseconds()
			return result
		}
		conn.SetDeadline(time.Now().Add(time.Duration(config.TimeoutMs) * time.Millisecond))
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		conn.Close()

		result.HTTPMs = time.Since(sshStart).Milliseconds()
		result.TotalMs = time.Since(totalStart).Milliseconds()

		if err != nil {
			result.Error = fmt.Sprintf("ssh banner: %v", err)
			return result
		}
		if n >= 4 && string(buf[:4]) == "SSH-" {
			result.Success = true
			result.HTTPStatus = 200 // synthetic — banner received
		} else {
			result.Error = "no SSH banner"
		}
		return result
	}

	// Non-SSH: HTTP request through SOCKS5 tunnel
	httpStart := time.Now()
	dialer, err := proxy.SOCKS5("tcp", listenAddr, nil, proxy.Direct)
	if err != nil {
		result.Error = fmt.Sprintf("socks5 dialer: %v", err)
		result.TotalMs = time.Since(totalStart).Milliseconds()
		return result
	}

	httpClient := &http.Client{
		Timeout: time.Duration(config.TimeoutMs) * time.Millisecond,
		Transport: &http.Transport{
			Dial:                dialer.Dial,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := httpClient.Get(e2eTestURL)
	if err != nil {
		errMsg := err.Error()
		// Simplify common errors
		if strings.Contains(errMsg, "context deadline exceeded") || strings.Contains(errMsg, "Timeout") {
			errMsg = "HTTP timeout"
		} else if strings.Contains(errMsg, "connection refused") {
			errMsg = "connection refused"
		} else if len(errMsg) > 50 {
			errMsg = errMsg[:50]
		}
		result.Error = errMsg
		result.TotalMs = time.Since(totalStart).Milliseconds()
		return result
	}
	resp.Body.Close()

	result.HTTPMs = time.Since(httpStart).Milliseconds()
	result.HTTPStatus = resp.StatusCode
	result.TotalMs = time.Since(totalStart).Milliseconds()

	// 204 = success for generate_204
	if resp.StatusCode == 204 || resp.StatusCode == 200 {
		result.Success = true
	} else {
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	return result
}

func waitForPort(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
