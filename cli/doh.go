package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http2"
)

// connectDoH starts a local DNS proxy that forwards queries to a DoH server via HTTPS.
// Listens on UDP and TCP, forwards DNS queries as RFC 8484 HTTPS POST.
func connectDoH(profile *Profile) {
	dohURL := profile.DoHURL
	if dohURL == "" {
		// Derive from resolvers
		parts := resolverHost(profile.Resolvers)
		if parts != "" {
			dohURL = "https://" + parts + "/dns-query"
		}
	}
	if dohURL == "" {
		fmt.Fprintln(os.Stderr, "  Error: DoH URL is required. Set it in the config or provide a resolver.")
		return
	}

	listenAddr := fmt.Sprintf("%s:%d", profile.Host, profile.Port)

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Printf("║          SlipNet CLI  %-25s  ║\n", version)
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Profile:    %s\n", profile.Name)
	fmt.Printf("  Type:       DNS over HTTPS\n")
	fmt.Printf("  DoH Server: %s\n", dohURL)
	fmt.Printf("  DNS Proxy:  %s (UDP + TCP)\n", listenAddr)
	fmt.Println()
	fmt.Println("  Starting DoH proxy...")

	client := newDoHClient()

	// Start UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Error: %v\n", err)
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Error: %v\n", err)
		return
	}
	defer udpConn.Close()

	// Start TCP listener
	tcpLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Error: %v\n", err)
		return
	}
	defer tcpLn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// UDP handler
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			query := make([]byte, n)
			copy(query, buf[:n])
			go func(q []byte, a *net.UDPAddr) {
				resp := dohQuery(client, dohURL, q)
				if resp != nil {
					udpConn.WriteToUDP(resp, a)
				}
			}(query, addr)
		}
	}()

	// TCP handler (DNS over TCP: 2-byte length prefix)
	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			go handleDoHTCP(conn, client, dohURL)
		}
	}()

	fmt.Println()
	fmt.Printf("  DoH proxy running on %s\n", listenAddr)
	fmt.Println()
	fmt.Println("  Configure your system DNS to use this proxy:")
	fmt.Printf("    DNS server: %s port %d\n", profile.Host, profile.Port)
	fmt.Println()
	fmt.Println("  Or test with dig:")
	fmt.Printf("    dig @%s -p %d example.com\n", profile.Host, profile.Port)
	fmt.Println()
	fmt.Println("  Press Ctrl+C to stop.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Println("\n  Stopping...")
	cancel()
	fmt.Println("  Done.")
}

// newDoHClient creates an HTTP client optimized for DoH with HTTP/2.
func newDoHClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{},
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	http2.ConfigureTransport(transport)
	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
}

// dohQuery sends a DNS query to the DoH server via HTTPS POST (RFC 8484).
func dohQuery(client *http.Client, dohURL string, query []byte) []byte {
	req, err := http.NewRequest("POST", dohURL, bytes.NewReader(query))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	return body
}

// handleDoHTCP handles a DNS-over-TCP connection (2-byte length prefix per message).
func handleDoHTCP(conn net.Conn, client *http.Client, dohURL string) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	var wg sync.WaitGroup
	for {
		// Read 2-byte length prefix
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if msgLen < 12 || msgLen > 65535 {
			return
		}

		query := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}

		wg.Add(1)
		go func(q []byte) {
			defer wg.Done()
			resp := dohQuery(client, dohURL, q)
			if resp == nil {
				return
			}
			// Write 2-byte length prefix + response
			out := make([]byte, 2+len(resp))
			out[0] = byte(len(resp) >> 8)
			out[1] = byte(len(resp) & 0xFF)
			copy(out[2:], resp)
			conn.Write(out)
		}(query)
	}
}

// resolverHost extracts the first host from a resolver string like "8.8.8.8:53:0".
func resolverHost(resolvers string) string {
	if resolvers == "" {
		return ""
	}
	parts := splitFirst(resolvers, ",")
	subParts := splitFirst(parts, ":")
	return subParts
}

func splitFirst(s, sep string) string {
	for i := 0; i < len(s); i++ {
		if string(s[i]) == sep {
			return s[:i]
		}
	}
	return s
}
