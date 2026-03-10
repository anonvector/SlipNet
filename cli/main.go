// slipnet is a cross-platform CLI client for SlipNet/NoizDNS.
//
// Usage:
//
//	slipnet [--dns RESOLVER] [--port PORT] slipnet://BASE64ENCODED...
//
// It decodes the slipnet:// URI, extracts connection parameters,
// and starts a local SOCKS5 proxy tunneled through DNS.
// If the tunnel domain can't be resolved via the profile's DNS resolver,
// it automatically falls back to the authoritative server.
package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"noizdns/mobile"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

// Profile fields (v16 pipe-delimited format)
type Profile struct {
	Version      string
	TunnelType   string // "sayedns" = NoizDNS, "dnstt" = DNSTT
	Name         string
	Domain       string
	Resolvers    string // e.g. "8.8.8.8:53:0"
	AuthMode     bool
	KeepAlive    int
	CC           string // congestion control: bbr, dcubic
	Port         int    // local SOCKS5 port
	Host         string // local SOCKS5 host
	GSO          bool
	PublicKey    string
	DNSTransport string // udp, tcp, tls (DoT), https (DoH)
	DoHURL       string
}

func parseURI(uri string) (*Profile, error) {
	const scheme = "slipnet://"
	if !strings.HasPrefix(uri, scheme) {
		return nil, fmt.Errorf("invalid URI scheme, expected slipnet://")
	}

	encoded := strings.TrimPrefix(uri, scheme)
	// Strip any whitespace/newlines from terminal line wrapping
	encoded = strings.Join(strings.Fields(encoded), "")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try with padding
		for len(encoded)%4 != 0 {
			encoded += "="
		}
		decoded, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("base64 decode failed: %v", err)
		}
	}

	fields := strings.Split(string(decoded), "|")
	if len(fields) < 12 {
		return nil, fmt.Errorf("not enough fields in profile (got %d, need at least 12)", len(fields))
	}

	p := &Profile{
		Version:    fields[0],
		TunnelType: fields[1],
		Name:       fields[2],
		Domain:     fields[3],
		Resolvers:  fields[4],
		Host:       "127.0.0.1",
		Port:       1080,
	}

	if fields[5] == "1" {
		p.AuthMode = true
	}

	if v, err := strconv.Atoi(fields[6]); err == nil {
		p.KeepAlive = v
	}
	p.CC = fields[7]

	if v, err := strconv.Atoi(fields[8]); err == nil && v > 0 {
		p.Port = v
	}
	if fields[9] != "" {
		p.Host = fields[9]
	}
	if fields[10] == "1" {
		p.GSO = true
	}
	p.PublicKey = fields[11]

	// DNS transport (field index 22 in v16)
	if len(fields) > 22 && fields[22] != "" {
		p.DNSTransport = fields[22]
	}
	// DoH URL (field index 21 in v16)
	if len(fields) > 21 && fields[21] != "" {
		p.DoHURL = fields[21]
	}

	return p, nil
}

// formatDNSAddr formats the DNS resolver address based on transport type
func formatDNSAddr(p *Profile) string {
	resolverParts := strings.Split(p.Resolvers, ",")
	var addrs []string

	for _, r := range resolverParts {
		parts := strings.Split(strings.TrimSpace(r), ":")
		if len(parts) < 1 {
			continue
		}

		host := parts[0]
		port := "53"
		if len(parts) >= 2 && parts[1] != "" {
			port = parts[1]
		}

		switch p.DNSTransport {
		case "https", "doh":
			if p.DoHURL != "" {
				return p.DoHURL
			}
			return fmt.Sprintf("https://%s/dns-query", host)
		case "tls", "dot":
			if port == "53" {
				port = "853"
			}
			addrs = append(addrs, fmt.Sprintf("tls://%s:%s", host, port))
		case "tcp":
			addrs = append(addrs, fmt.Sprintf("tcp://%s:%s", host, port))
		default: // udp
			addrs = append(addrs, fmt.Sprintf("%s:%s", host, port))
		}
	}

	return strings.Join(addrs, ",")
}

// findAuthoritativeServer resolves the authoritative server IP for the tunnel
// domain. It first tries NS record lookup, then falls back to the
// "ns.<parent-domain>" convention. Returns the IP or empty string.
func findAuthoritativeServer(tunnelDomain string) string {
	nss, err := net.LookupNS(tunnelDomain)
	if err == nil && len(nss) > 0 {
		return resolveNSHost(nss)
	}
	return findServerFallback(tunnelDomain)
}

// resolveNSHost resolves the first NS record hostname to an IP.
func resolveNSHost(nss []*net.NS) string {
	nsHost := strings.TrimSuffix(nss[0].Host, ".")
	ips, err := net.LookupHost(nsHost)
	if err == nil && len(ips) > 0 {
		return ips[0]
	}
	return ""
}

// findServerFallback tries the "ns.<parent-domain>" convention.
func findServerFallback(tunnelDomain string) string {
	parts := strings.SplitN(tunnelDomain, ".", 2)
	if len(parts) < 2 {
		return ""
	}
	nsHost := "ns." + parts[1]
	ips, err := net.LookupHost(nsHost)
	if err == nil && len(ips) > 0 {
		return ips[0]
	}
	return ""
}

func main() {
	var portOverride int
	var dnsOverride string
	var forceDirectMode bool
	var uriParts []string

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--dns", "-dns":
			if i+1 < len(os.Args) {
				dnsOverride = os.Args[i+1]
				i++
			} else {
				log.Fatal("--dns requires a value (e.g., --dns 1.1.1.1 or --dns <server-ip>)")
			}
		case "--port", "-port":
			if i+1 < len(os.Args) {
				v, err := strconv.Atoi(os.Args[i+1])
				if err != nil || v < 1 || v > 65535 {
					log.Fatal("--port requires a valid port number (1-65535)")
				}
				portOverride = v
				i++
			} else {
				log.Fatal("--port requires a value")
			}
		case "--direct", "-direct":
			forceDirectMode = true
		case "--version", "-version", "-v":
			fmt.Printf("slipnet %s\n", version)
			os.Exit(0)
		case "--help", "-help", "-h":
			printUsage()
			os.Exit(0)
		default:
			uriParts = append(uriParts, os.Args[i])
		}
	}

	if len(uriParts) == 0 {
		printUsage()
		os.Exit(1)
	}

	// Join all non-flag args in case terminal line-wrapping split the URI
	uri := strings.TrimSpace(strings.Join(uriParts, ""))
	profile, err := parseURI(uri)
	if err != nil {
		log.Fatalf("Failed to parse URI: %v", err)
	}

	// Validate tunnel type — CLI only supports DNSTT and NoizDNS
	switch profile.TunnelType {
	case "dnstt", "dnstt_ssh", "sayedns", "sayedns_ssh":
		// supported
	case "ss", "slipstream_ssh", "ssh", "doh", "snowflake", "naive_ssh", "naive":
		log.Fatalf("This config uses tunnel type %q which is not supported by the CLI.\n"+
			"SlipNet CLI only supports DNSTT and NoizDNS tunnel types.\n"+
			"Use the SlipNet app for other tunnel types.", profile.TunnelType)
	default:
		if profile.TunnelType != "" {
			log.Fatalf("Unknown tunnel type %q in config", profile.TunnelType)
		}
	}

	if profile.PublicKey == "" {
		log.Fatal("Config is missing the server's public key.\n" +
			"The slipnet:// URI must include the server's Noise public key.\n" +
			"Ask your server admin for a config that includes the public key,\n" +
			"or re-export the config from the SlipNet app.")
	}
	if profile.Domain == "" {
		log.Fatal("Profile is missing tunnel domain")
	}

	if portOverride > 0 {
		profile.Port = portOverride
	}

	dnsAddr := formatDNSAddr(profile)
	authMode := profile.AuthMode
	directMode := false

	if dnsOverride != "" {
		// User specified custom DNS resolver
		if !strings.Contains(dnsOverride, ":") && !strings.HasPrefix(dnsOverride, "https://") && !strings.HasPrefix(dnsOverride, "tls://") {
			dnsOverride += ":53"
		}
		dnsAddr = dnsOverride
		if forceDirectMode {
			directMode = true
			authMode = true
		}
		fmt.Printf("  Using custom DNS: %s\n", dnsAddr)
	} else if forceDirectMode {
		directMode = true
		authMode = true
	}

	if dnsOverride == "" {
		fmt.Printf("  Checking DNS for %s...\n", profile.Domain)
		if forceDirectMode {
			// --direct: find the server IP and connect directly
			serverIP := findAuthoritativeServer(profile.Domain)
			if serverIP != "" {
				fmt.Printf("  Found server at %s, using direct mode\n", serverIP)
				dnsAddr = serverIP + ":53"
			} else {
				fmt.Printf("  Warning: could not auto-detect server IP, trying profile resolver\n")
			}
		} else {
			// Auto-detect: check if DNS delegation works
			nss, nsErr := net.LookupNS(profile.Domain)
			if nsErr != nil {
				fmt.Printf("  DNS delegation not available via public DNS\n")
				// NS lookup already failed — skip it in findAuthoritativeServer
				// and go straight to the fallback.
				serverIP := findServerFallback(profile.Domain)
				if serverIP != "" {
					fmt.Printf("  Found server at %s, using direct mode\n", serverIP)
					dnsAddr = serverIP + ":53"
					authMode = true
					directMode = true
				} else {
					fmt.Printf("  Warning: could not auto-detect server IP, trying profile resolver\n")
				}
			} else if len(nss) > 0 {
				fmt.Printf("  DNS delegation OK\n")
			}
		}
	}

	listenAddr := fmt.Sprintf("%s:%d", profile.Host, profile.Port)

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Printf("║          SlipNet CLI  %-25s  ║\n", version)
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Profile:    %s\n", profile.Name)
	fmt.Printf("  Type:       %s\n", profile.TunnelType)
	fmt.Printf("  Domain:     %s\n", profile.Domain)
	fmt.Printf("  DNS:        %s\n", dnsAddr)
	if directMode {
		fmt.Println("              (direct to server, auto-detected)")
	}
	transport := profile.DNSTransport
	if transport == "" {
		transport = "udp"
	}
	fmt.Printf("  Transport:  %s\n", transport)
	fmt.Printf("  Auth Mode:  %v\n", authMode)
	if len(profile.PublicKey) > 16 {
		fmt.Printf("  Public Key: %s...%s\n", profile.PublicKey[:8], profile.PublicKey[len(profile.PublicKey)-8:])
	} else {
		fmt.Printf("  Public Key: %s\n", profile.PublicKey)
	}
	fmt.Println()
	fmt.Printf("  SOCKS5 Proxy: %s\n", listenAddr)
	fmt.Println()
	fmt.Println("  Connecting...")

	client, err := mobile.NewClient(dnsAddr, profile.Domain, profile.PublicKey, listenAddr)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	client.SetAuthoritativeMode(authMode)

	// Enable NoizDNS mode for sayedns profiles
	if profile.TunnelType == "sayedns" || profile.TunnelType == "sayedns_ssh" {
		client.SetNoizMode(true)
	}

	if err := client.Start(); err != nil {
		log.Fatalf("Failed to start tunnel: %v", err)
	}

	fmt.Println()
	fmt.Printf("  Connected! SOCKS5 proxy listening on %s\n", listenAddr)
	fmt.Println()
	fmt.Println("  Configure your apps to use:")
	fmt.Printf("    SOCKS5 proxy: %s\n", listenAddr)
	fmt.Println()
	fmt.Println("  Or use with curl:")
	fmt.Printf("    curl --socks5-hostname %s https://ifconfig.me\n", listenAddr)
	fmt.Println()
	fmt.Println("  If the server requires SOCKS5 authentication:")
	fmt.Printf("    curl --socks5-hostname user:pass@%s https://ifconfig.me\n", listenAddr)
	fmt.Println()
	fmt.Println("  Press Ctrl+C to disconnect.")

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println()
	fmt.Println("  Disconnecting...")
	done := make(chan struct{})
	go func() { client.Stop(); close(done) }()
	select {
	case <-done:
		fmt.Println("  Done.")
	case <-time.After(5 * time.Second):
		fmt.Println("  Shutdown timed out, forcing exit.")
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `SlipNet CLI %s - DNS tunnel SOCKS5 proxy

Usage:
  %s [options] slipnet://BASE64...

Options:
  --dns HOST[:PORT]   Custom DNS resolver (e.g., --dns 1.1.1.1 or --dns <server-ip>)
  --direct            Connect directly to server (authoritative mode)
  --port PORT         Override local SOCKS5 proxy port (default: from profile)
  --version           Show version
  --help              Show this help

If no --dns is specified, the client auto-detects the server IP
when DNS delegation isn't working.

Examples:
  %[2]s slipnet://BASE64...
  %[2]s --dns 1.1.1.1 slipnet://BASE64...
  %[2]s --dns <server-ip> --direct --port 9050 slipnet://BASE64...
`, version, os.Args[0])
}
