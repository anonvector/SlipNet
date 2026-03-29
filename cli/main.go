// slipnet is a cross-platform CLI client for SlipNet/NoizDNS.
//
// Usage:
//
//	slipnet [--dns RESOLVER] [--port PORT] [--host HOST] [--max-query-size BYTES] slipnet://BASE64ENCODED...
//
// It decodes the slipnet:// URI, extracts connection parameters,
// and starts a local SOCKS5 proxy tunneled through DNS.
// If the tunnel domain can't be resolved via the profile's DNS resolver,
// it automatically falls back to the authoritative server.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"noizdns/mobile"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

// Profile fields (v18 pipe-delimited format)
type Profile struct {
	Version       string
	TunnelType    string // "sayedns" = NoizDNS, "dnstt" = DNSTT, "ssh", "socks5", etc.
	Name          string
	Domain        string
	Resolvers     string // e.g. "8.8.8.8:53:0"
	AuthMode      bool
	KeepAlive     int
	CC            string // congestion control: bbr, dcubic
	Port          int    // local SOCKS5 port
	Host          string // local SOCKS5 host
	GSO           bool
	PublicKey     string
	SOCKSUser     string
	SOCKSPass     string
	SSHEnabled    bool
	SSHUser       string
	SSHPass       string
	SSHPort       int
	SSHHost       string
	DNSTransport  string // udp, tcp, tls (DoT), https (DoH)
	DoHURL        string
}

func parseURI(uri string) (*Profile, error) {
	const scheme = "slipnet://"
	const encScheme = "slipnet-enc://"

	var encoded string
	var encrypted bool

	switch {
	case strings.HasPrefix(uri, encScheme):
		encoded = strings.TrimPrefix(uri, encScheme)
		encrypted = true
	case strings.HasPrefix(uri, scheme):
		encoded = strings.TrimPrefix(uri, scheme)
	default:
		return nil, fmt.Errorf("invalid URI scheme, expected slipnet:// or slipnet-enc://")
	}

	// Strip any whitespace/newlines from terminal line wrapping
	encoded = strings.Join(strings.Fields(encoded), "")
	rawBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try with padding
		for len(encoded)%4 != 0 {
			encoded += "="
		}
		rawBytes, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("base64 decode failed: %v", err)
		}
	}

	var decoded []byte
	if encrypted {
		plaintext, err := decryptConfig(rawBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt config: %v", err)
		}
		decoded = []byte(plaintext)
	} else {
		decoded = rawBytes
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
		Port:       10880,
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

	// SOCKS credentials (fields 12-13)
	if len(fields) > 13 {
		p.SOCKSUser = fields[12]
		p.SOCKSPass = fields[13]
	}
	// SSH fields (14-19)
	if len(fields) > 19 {
		p.SSHEnabled = fields[14] == "1"
		p.SSHUser = fields[15]
		p.SSHPass = fields[16]
		if v, err := strconv.Atoi(fields[17]); err == nil && v > 0 {
			p.SSHPort = v
		} else {
			p.SSHPort = 22
		}
		p.SSHHost = fields[19]
	}
	// DoH URL (field 21)
	if len(fields) > 21 && fields[21] != "" {
		p.DoHURL = fields[21]
	}
	// DNS transport (field 22)
	if len(fields) > 22 && fields[22] != "" {
		p.DNSTransport = fields[22]
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
	// Check for "scan" subcommand first
	if len(os.Args) >= 2 && os.Args[1] == "scan" {
		runScanCommand(os.Args[2:])
		return
	}

	var portOverride int
	var dnsOverride string
	var utlsOverride string
	var hostOverride string
	var forceDirectMode bool
	var querySize int
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
		case "--host", "-host":
			if i+1 < len(os.Args) {
				hostOverride = os.Args[i+1]
				i++
			} else {
				log.Fatal("--host requires a value (e.g., --host 0.0.0.0)")
			}
		case "--utls", "-utls":
			if i+1 < len(os.Args) {
				utlsOverride = os.Args[i+1]
				i++
			} else {
				log.Fatal("--utls requires a value (e.g., --utls Chrome_120, --utls none)")
			}
		case "--max-query-size", "-mqs", "--query-size":
			if i+1 < len(os.Args) {
				v, err := strconv.Atoi(os.Args[i+1])
				if err != nil || v < 50 {
					log.Fatal("--max-query-size requires a value >= 50 (bytes)")
				}
				querySize = v
				i++
			} else {
				log.Fatal("--max-query-size requires a value (e.g., --max-query-size 100)")
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
		// No args — launch interactive menu (for double-click users)
		runInteractive()
		return
	}

	// Join all non-flag args in case terminal line-wrapping split the URI
	uri := strings.TrimSpace(strings.Join(uriParts, ""))
	connectWithParams(uri, portOverride, hostOverride, dnsOverride, utlsOverride, forceDirectMode, querySize)
}

// connectWithParams runs the tunnel connection with the given parameters.
func connectWithParams(uri string, portOverride int, hostOverride string, dnsOverride string, utlsOverride string, forceDirectMode bool, querySize int) {
	profile, err := parseURI(uri)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Error: Failed to parse URI: %v\n", err)
		return
	}

	if hostOverride != "" {
		profile.Host = hostOverride
	}

	// Validate tunnel type
	switch profile.TunnelType {
	case "dnstt", "dnstt_ssh", "sayedns", "sayedns_ssh":
		// DNSTT/NoizDNS — handled below via noizdns/mobile
	case "ssh", "direct_ssh":
		if portOverride > 0 {
			profile.Port = portOverride
		}
		connectSSHTunnel(profile)
		return
	case "socks5", "direct_socks":
		if portOverride > 0 {
			profile.Port = portOverride
		}
		connectSOCKS5(profile)
		return
	case "ss", "slipstream_ssh", "doh", "snowflake", "naive":
		fmt.Fprintf(os.Stderr, "  Error: This config uses tunnel type %q which is not supported by the CLI.\n"+
			"  SlipNet CLI supports DNSTT, NoizDNS, SSH, and SOCKS5 tunnel types.\n"+
			"  Use the SlipNet app for other tunnel types.\n", profile.TunnelType)
		return
	default:
		if profile.TunnelType != "" {
			fmt.Fprintf(os.Stderr, "  Error: Unknown tunnel type %q in config\n", profile.TunnelType)
			return
		}
	}

	if profile.PublicKey == "" {
		fmt.Fprintln(os.Stderr, "  Error: Config is missing the server's public key.\n"+
			"  The slipnet:// URI must include the server's Noise public key.\n"+
			"  Ask your server admin for a config that includes the public key,\n"+
			"  or re-export the config from the SlipNet app.")
		return
	}
	if profile.Domain == "" {
		fmt.Fprintln(os.Stderr, "  Error: Profile is missing tunnel domain")
		return
	}

	if portOverride > 0 {
		profile.Port = portOverride
	}

	dnsAddr := formatDNSAddr(profile)
	authMode := profile.AuthMode
	directMode := false

	if dnsOverride != "" {
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
			serverIP := findAuthoritativeServer(profile.Domain)
			if serverIP != "" {
				fmt.Printf("  Found server at %s, using direct mode\n", serverIP)
				dnsAddr = serverIP + ":53"
			} else {
				fmt.Printf("  Warning: could not auto-detect server IP, trying profile resolver\n")
			}
		} else {
			nss, nsErr := net.LookupNS(profile.Domain)
			if nsErr != nil {
				fmt.Printf("  DNS delegation not available via public DNS\n")
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
	if querySize > 0 {
		fmt.Printf("  Query Size: %d bytes\n", querySize)
	}
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
		fmt.Fprintf(os.Stderr, "  Error: Failed to create client: %v\n", err)
		return
	}

	client.SetAuthoritativeMode(authMode)

	if profile.TunnelType == "sayedns" || profile.TunnelType == "sayedns_ssh" {
		client.SetNoizMode(true)
	}

	if querySize > 0 {
		client.SetMaxPayload(querySize)
	}

	if utlsOverride != "" {
		client.SetUTLSFingerprint(utlsOverride)
		fmt.Printf("  uTLS:       %s\n", utlsOverride)
	}

	// Only inject SOCKS5 auth for pure SOCKS5 tunnel types.
	// dnstt_ssh/sayedns_ssh carry raw SSH, not SOCKS5.
	isSocks5Tunnel := profile.TunnelType == "dnstt" || profile.TunnelType == "sayedns" || profile.TunnelType == ""
	if profile.SOCKSUser != "" && isSocks5Tunnel {
		client.SetSocksCredentials(profile.SOCKSUser, profile.SOCKSPass)
		fmt.Printf("  SOCKS5 Auth: enabled (injected automatically)\n")
	}

	if err := client.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "  Error: Failed to start tunnel: %v\n", err)
		return
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
	fmt.Println("  Press Ctrl+C to disconnect.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Monitor tunnel health and auto-reconnect when session dies.
	reconnectDelay := 3 * time.Second
	for {
		select {
		case <-sigCh:
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
			return
		case <-time.After(5 * time.Second):
			if !client.IsRunning() {
				fmt.Printf("\n  Tunnel died, reconnecting in %v...\n", reconnectDelay)
				client.Stop()
				time.Sleep(reconnectDelay)

				client, err = mobile.NewClient(dnsAddr, profile.Domain, profile.PublicKey, listenAddr)
				if err != nil {
					fmt.Printf("  Failed to create client: %v\n", err)
					continue
				}
				client.SetAuthoritativeMode(authMode)
				if profile.TunnelType == "sayedns" || profile.TunnelType == "sayedns_ssh" {
					client.SetNoizMode(true)
				}
				if querySize > 0 {
					client.SetMaxPayload(querySize)
				}
				if utlsOverride != "" {
					client.SetUTLSFingerprint(utlsOverride)
				}
				if profile.SOCKSUser != "" && isSocks5Tunnel {
					client.SetSocksCredentials(profile.SOCKSUser, profile.SOCKSPass)
				}

				if err := client.Start(); err != nil {
					fmt.Printf("  Reconnect failed: %v\n", err)
					continue
				}
				fmt.Println("  Reconnected!")
			}
		}
	}
}

func runScanCommand(args []string) {
	var domain string
	var ipsFile string
	var singleIP string
	var timeoutMs = 3000
	var concurrency = 100
	var port = 53
	var e2eEnabled bool
	var pubkey string
	var noizdns bool
	var e2eConcurrency = 10
	var e2eTimeout = 15000
	var e2eURL string
	var e2eThreshold = 2
	var configURI string
	var verifyMode bool
	var prismTimeout = 0 // 0 = use --timeout value
	var verifyRounds = 5
	var passThreshold = 2
	var responseSize int
	var querySize int
	var prismPrefilter bool
	var e2eOnly bool
	var outputFile string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--domain", "-domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		case "--ips", "-ips":
			if i+1 < len(args) {
				ipsFile = args[i+1]
				i++
			}
		case "--ip", "-ip":
			if i+1 < len(args) {
				singleIP = args[i+1]
				i++
			}
		case "--timeout", "-timeout":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v > 0 {
					timeoutMs = v
				}
				i++
			}
		case "--concurrency", "-concurrency":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v > 0 {
					concurrency = v
				}
				i++
			}
		case "--port", "-port":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v > 0 {
					port = v
				}
				i++
			}
		case "--e2e":
			e2eEnabled = true
		case "--pubkey", "-pubkey":
			if i+1 < len(args) {
				pubkey = args[i+1]
				i++
			}
		case "--noizdns":
			noizdns = true
		case "--e2e-concurrency":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v > 0 {
					e2eConcurrency = v
				}
				i++
			}
		case "--e2e-timeout":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v > 0 {
					e2eTimeout = v
				}
				i++
			}
		case "--e2e-threshold":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v >= 0 && v <= 6 {
					e2eThreshold = v
				}
				i++
			}
		case "--e2e-url":
			if i+1 < len(args) {
				e2eURL = args[i+1]
				i++
			}
		case "--verify", "-verify":
			verifyMode = true
		case "--probes", "-probes", "--rounds", "-rounds":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v > 0 {
					verifyRounds = v
				}
				i++
			}
		case "--threshold", "-threshold":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v > 0 {
					passThreshold = v
				}
				i++
			}
		case "--response-size", "-response-size":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v > 0 {
					responseSize = v
				}
				i++
			}
		case "--prism-timeout", "-prism-timeout":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v > 0 {
					prismTimeout = v
				}
				i++
			}
		case "--prefilter", "-prefilter":
			prismPrefilter = true
		case "--e2e-only":
			e2eOnly = true
		case "--config", "-config":
			if i+1 < len(args) {
				configURI = args[i+1]
				i++
			}
		case "--max-query-size", "-mqs", "--query-size", "-query-size":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v >= 50 {
					querySize = v
				}
				i++
			}
		case "--output", "-output", "-o":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "--help", "-help", "-h":
			printUsage()
			os.Exit(0)
		}
	}

	// If --config is provided, extract domain, pubkey, noizdns, and ssh mode from slipnet:// URI
	var sshMode bool
	var socksUser, socksPass string
	if configURI != "" {
		profile, err := parseURI(configURI)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Error: Failed to parse config URI: %v\n", err)
			return
		}
		if domain == "" {
			domain = profile.Domain
		}
		if pubkey == "" {
			pubkey = profile.PublicKey
		}
		if profile.TunnelType == "sayedns" || profile.TunnelType == "sayedns_ssh" {
			noizdns = true
		}
		if profile.TunnelType == "dnstt_ssh" || profile.TunnelType == "sayedns_ssh" {
			sshMode = true
		}
		socksUser = profile.SOCKSUser
		socksPass = profile.SOCKSPass
		// If e2e flag not explicitly set but pubkey is available, enable it
		if pubkey != "" && !e2eEnabled {
			e2eEnabled = true
		}
	}

	if domain == "" {
		fmt.Fprintln(os.Stderr, "  Error: scan requires --domain (e.g., --domain t.example.com)")
		return
	}
	var resolvers []string
	if singleIP != "" {
		resolvers = []string{singleIP}
	} else if ipsFile != "" {
		data, err := os.ReadFile(ipsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Error: Failed to read IP list file: %v\n", err)
			return
		}
		resolvers = LoadIPList(string(data))
		if len(resolvers) == 0 {
			fmt.Fprintln(os.Stderr, "  Error: No valid IP addresses found in file")
			return
		}
	} else {
		resolvers = LoadIPList(string(defaultResolverList))
		fmt.Printf("  Using built-in resolver list (%d IPs)\n", len(resolvers))
	}

	if verifyMode {
		if pubkey == "" {
			fmt.Fprintln(os.Stderr, "  Error: verify mode requires --pubkey or --config with a slipnet:// URI")
			return
		}
		pubkeyBytes, err := hex.DecodeString(pubkey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Error: invalid pubkey hex: %v\n", err)
			return
		}
		prismTimeoutMs := prismTimeout
		if prismTimeoutMs <= 0 {
			prismTimeoutMs = timeoutMs
		}
		// If E2E flags are provided, run E2E on verified resolvers after prism.
		var prismE2E *E2EConfig
		if e2eEnabled {
			prismE2E = &E2EConfig{
				TunnelDomain: domain,
				PublicKey:     pubkey,
				NoizMode:      noizdns,
				SSHMode:       sshMode,
				TimeoutMs:     e2eTimeout,
				Concurrency:   e2eConcurrency,
				QuerySize:     querySize,
				SOCKSUser:     socksUser,
				SOCKSPass:     socksPass,
				TestURL:       e2eURL,
			}
		}
		RunVerifyScanner(resolvers, domain, port, prismTimeoutMs, concurrency, verifyRounds, passThreshold, pubkeyBytes, responseSize, prismPrefilter, prismE2E, outputFile)
		return
	}

	if e2eOnly {
		if pubkey == "" {
			fmt.Fprintln(os.Stderr, "  Error: E2E-only mode requires --pubkey or --config with a slipnet:// URI")
			return
		}
		e2eOnlyConfig := E2EConfig{
			TunnelDomain: domain,
			PublicKey:     pubkey,
			NoizMode:      noizdns,
			SSHMode:       sshMode,
			TimeoutMs:     e2eTimeout,
			Concurrency:   e2eConcurrency,
			QuerySize:     querySize,
			SOCKSUser:     socksUser,
			SOCKSPass:     socksPass,
			TestURL:       e2eURL,
		}
		RunE2EOnlyScanner(resolvers, e2eOnlyConfig, outputFile)
		return
	}

	var e2eConfig *E2EConfig
	if e2eEnabled {
		if pubkey == "" {
			fmt.Fprintln(os.Stderr, "  Error: E2E testing requires --pubkey or --config with a slipnet:// URI")
			return
		}
		e2eConfig = &E2EConfig{
			TunnelDomain:   domain,
			PublicKey:       pubkey,
			NoizMode:        noizdns,
			SSHMode:         sshMode,
			TimeoutMs:       e2eTimeout,
			Concurrency:     e2eConcurrency,
			QuerySize:       querySize,
			ScoreThreshold:  e2eThreshold,
			SOCKSUser:       socksUser,
			TestURL:         e2eURL,
			SOCKSPass:       socksPass,
		}
	}

	RunScanner(resolvers, domain, port, timeoutMs, concurrency, querySize, e2eConfig, outputFile)
}

func printUsage() {
	prog := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, `SlipNet CLI %s - Tunnel proxy (DNSTT, NoizDNS, SSH, SOCKS5)

Usage:
  %s [options] slipnet://BASE64...
  %[2]s [options] slipnet-enc://BASE64...
  %[2]s scan [options] --domain DOMAIN --ips FILE

Options (connect):
  --dns HOST[:PORT]   Custom DNS resolver (e.g., --dns 1.1.1.1 or --dns <server-ip>)
  --direct            Connect directly to server (authoritative mode)
  --port PORT         Override local SOCKS5 proxy port (default: from profile)
  --host HOST         Override local SOCKS5 proxy listen address (default: 127.0.0.1)
                      Use 0.0.0.0 to allow connections from other devices on the network
  --utls FINGERPRINT  Fix TLS fingerprint (default: random from distribution)
                      Examples: Chrome_120, Firefox_120, iOS_14, random, none
                      Weighted: "3*Chrome_120,1*Firefox_120"
  --max-query-size BYTES, -mqs BYTES
                      Max DNS query payload size in bytes (default: full capacity)
                      Lower values produce smaller queries for restrictive networks
                      Minimum: 50. Presets: 100 (large), 80 (medium), 60 (small), 50 (minimum)
  --version           Show version
  --help              Show this help

Options (scan):
  --domain DOMAIN     Tunnel domain to test (required unless --config given)
  --ips FILE          File with resolver IPs, one per line (or use --ip for single)
  --ip IP             Single resolver IP to scan
  --timeout MS        Per-query timeout in ms (default: 3000)
  --concurrency N     Parallel DNS scans (default: 100)
  --port PORT         DNS port (default: 53)
  --e2e               Run E2E tunnel test on resolvers meeting score threshold
  --e2e-only          E2E test only: skip DNS scan, test resolvers directly
  --pubkey KEY        Server public key for E2E (required with --e2e/--e2e-only)
  --noizdns           Use NoizDNS mode for E2E (default: DNSTT)
  --e2e-concurrency N Parallel E2E tests (default: 10)
  --e2e-timeout MS    E2E HTTP timeout in ms (default: 15000)
  --e2e-url URL       Custom URL for E2E verification (default: gstatic generate_204)
  --e2e-threshold N   Minimum DNS score to qualify for E2E, 0-6 (default: 2)
  --config URI        Extract domain/pubkey/mode from slipnet:// URI (auto-enables E2E)
  --verify            Prism mode: server-verified scan to authenticate the tunnel server
                      Requires --pubkey or --config to provide the server's public key
                      Combine with --e2e to run E2E tunnel tests on verified resolvers
  --prism-timeout MS  Timeout per resolver for Prism mode (default: --timeout value)
  --probes N          Probes per resolver (default: 5, used with --verify)
  --threshold N       Required passing probes (default: 2, used with --verify)
  --response-size N   Request server to pad response to N bytes (used with --verify)
                      0 = server default, 200-4096 = custom size
  --prefilter         DNS pre-filter to skip dead IPs before Prism probes (off by default)
  --max-query-size BYTES, -mqs BYTES
                      Cap DNS probe and E2E tunnel query size (default: full capacity)
                      Matches connect --max-query-size so scan results reflect real usage
  --output FILE       Save results to FILE (skips interactive prompt)

If no --dns is specified, the client auto-detects the server IP
when DNS delegation isn't working.

Examples:
  %[2]s slipnet://BASE64...
  %[2]s --utls Chrome_120 slipnet://BASE64...
  %[2]s --dns 1.1.1.1 slipnet://BASE64...
  %[2]s --dns <server-ip> --direct --port 9050 slipnet://BASE64...
  %[2]s --max-query-size 80 slipnet://BASE64...
  %[2]s --host 0.0.0.0 slipnet://BASE64...
  %[2]s scan --domain t.example.com --ips resolvers.txt
  %[2]s scan --domain t.example.com --ip 8.8.8.8
  %[2]s scan --config slipnet://BASE64... --ips resolvers.txt
  %[2]s scan --domain t.example.com --ips ips.txt --e2e --pubkey HEXKEY
  %[2]s scan --config slipnet://BASE64... --ips resolvers.txt --verify
  %[2]s scan --config slipnet://BASE64... --ips resolvers.txt --e2e-only
  %[2]s scan --domain t.example.com --pubkey HEXKEY --ips resolvers.txt --verify --probes 3
`, version, prog)
}
