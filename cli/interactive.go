package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var reader *bufio.Reader

func prompt(label string) string {
	fmt.Print(label)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func promptDefault(label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Print(label + ": ")
	}
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func waitExit() {
	fmt.Println()
	fmt.Print("  Press Enter to exit...")
	reader.ReadString('\n')
}

func runInteractive() {
	reader = bufio.NewReader(os.Stdin)

	for {
		clearScreen()
		fmt.Println()
		fmt.Println("╔══════════════════════════════════════════════════╗")
		fmt.Printf("║          SlipNet CLI  %-25s  ║\n", version)
		fmt.Println("╠══════════════════════════════════════════════════╣")
		fmt.Println("║                                                  ║")
		fmt.Println("║  1) Connect (DNSTT / NoizDNS / VayDNS)           ║")
		fmt.Println("║  2) DNS Scanner                                  ║")
		fmt.Println("║  3) DNS Scanner + E2E Test                       ║")
		fmt.Println("║  4) Quick Scan (single IP)                       ║")
		fmt.Println("║  5) Prism (server-verified scan)                 ║")
		fmt.Println("║  6) E2E Test Only                                ║")
		fmt.Println("║  7) Help                                         ║")
		fmt.Println("║  0) Exit                                         ║")
		fmt.Println("║                                                  ║")
		fmt.Println("╚══════════════════════════════════════════════════╝")
		fmt.Println()

		choice := prompt("  Select option: ")

		switch choice {
		case "1":
			interactiveConnect()
		case "2":
			interactiveScan(false)
		case "3":
			interactiveScan(true)
		case "4":
			interactiveQuickScan()
		case "5":
			interactiveVerifyScan()
		case "6":
			interactiveE2EOnly()
		case "7":
			printUsage()
			waitExit()
		case "0", "q", "exit":
			fmt.Println("  Goodbye!")
			return
		default:
			// If they pasted a slipnet:// or slipnet-enc:// URI directly, treat as connect
			if isSlipnetURI(choice) {
				interactiveConnectWithURI(choice)
			}
		}
	}
}

func interactiveConnect() {
	fmt.Println()
	fmt.Println("  ── Connect ──────────────────────────────────────")
	fmt.Println()
	uri := prompt("  Paste slipnet:// or slipnet-enc:// config: ")
	if uri == "" {
		return
	}
	if !isSlipnetURI(uri) {
		fmt.Println("  Invalid config. Must start with slipnet:// or slipnet-enc://")
		waitExit()
		return
	}
	interactiveConnectWithURI(uri)
}

func interactiveConnectWithURI(uri string) {
	fmt.Println()

	// Parse to show profile info
	profile, err := parseURI(uri)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		waitExit()
		return
	}

	fmt.Printf("  Profile:  %s\n", profile.Name)
	fmt.Printf("  Type:     %s\n", profile.TunnelType)
	if profile.IsLocked {
		fmt.Println("  Domain:   [hidden]")
		user := profile.SSHUser
		if user == "" {
			user = profile.SOCKSUser
		}
		if user != "" {
			fmt.Printf("  User:     %s\n", user)
		}
	} else {
		fmt.Printf("  Domain:   %s\n", profile.Domain)
		if profile.Resolvers != "" {
			fmt.Printf("  Resolver: %s\n", formatResolverDisplay(profile.Resolvers))
		}
	}
	fmt.Println()

	// Check for unsupported tunnel types before prompting for overrides
	switch profile.TunnelType {
	case "ss", "slipstream_ssh", "snowflake", "naive":
		fmt.Printf("  This config uses tunnel type %q which is not supported by the CLI.\n", profile.TunnelType)
		fmt.Println("  SlipNet CLI supports DNSTT, NoizDNS, VayDNS, SSH, SOCKS5, and DoH tunnel types.")
		fmt.Println("  Use the SlipNet app for other tunnel types.")
		waitExit()
		return
	case "socks5", "direct_socks":
		if profile.SOCKSUser == "" && profile.SSHUser == "" {
			fmt.Println("  This SOCKS5 config has no SSH or SOCKS5 credentials.")
			fmt.Println("  The CLI needs SSH credentials to tunnel to the server's SOCKS5 proxy.")
			fmt.Println("  Add credentials to your config and re-export, or use the SlipNet app.")
			waitExit()
			return
		}
	}

	// Optional overrides
	portStr := promptDefault("  Local port", strconv.Itoa(profile.Port))
	if v, err := strconv.Atoi(portStr); err == nil && v > 0 {
		profile.Port = v
	}

	dnsHint := "blank = auto"
	if profile.Resolvers != "" && !profile.IsLocked {
		dnsHint = "blank = " + formatResolverDisplay(profile.Resolvers)
	}
	dnsOverride := promptDefault("  DNS override ("+dnsHint+")", "")
	var utlsOverride string
	if profile.DNSTransport == "https" || profile.DNSTransport == "doh" || profile.DNSTransport == "tls" || profile.DNSTransport == "dot" {
		utlsOverride = promptDefault("  uTLS fingerprint (blank = random)", "")
	}
	directStr := promptDefault("  Authoritative mode? (y/N)", "n")
	forceDirectMode := strings.HasPrefix(strings.ToLower(directStr), "y")

	var querySize int
	var maxQnameLen int

	isVaydns := profile.TunnelType == "vaydns" || profile.TunnelType == "vaydns_ssh"
	isDnstt := profile.TunnelType == "dnstt" || profile.TunnelType == "dnstt_ssh" || profile.TunnelType == "sayedns" || profile.TunnelType == "sayedns_ssh" || profile.TunnelType == ""

	if isDnstt && !isVaydns {
		qs := promptDefault("  DNS query size in bytes, 0 = full capacity (default: 0)", "0")
		if v, err := strconv.Atoi(qs); err == nil && v >= 50 {
			querySize = v
		}
	}

	if isVaydns {
		qn := promptDefault("  Max QNAME length 60–253, shorter = stealthier (default: 101)", "101")
		if v, err := strconv.Atoi(qn); err == nil && v >= 60 && v <= 253 && v != 101 {
			maxQnameLen = v
		}
	}

	// Build args and invoke the existing connect logic
	var args []string
	if dnsOverride != "" {
		args = append(args, "--dns", dnsOverride)
	}
	if utlsOverride != "" {
		args = append(args, "--utls", utlsOverride)
	}
	if forceDirectMode {
		args = append(args, "--direct")
	}
	if querySize > 0 {
		args = append(args, "--max-query-size", strconv.Itoa(querySize))
	}
	if maxQnameLen > 0 {
		args = append(args, "--max-qname-len", strconv.Itoa(maxQnameLen))
	}
	args = append(args, "--port", strconv.Itoa(profile.Port))
	args = append(args, uri)

	// Replace os.Args and re-run main connect logic
	origArgs := os.Args
	os.Args = append([]string{origArgs[0]}, args...)
	defer func() { os.Args = origArgs }()

	// Don't call main() recursively — just run the connect flow directly
	fmt.Println()
	fmt.Println("  Starting connection...")
	fmt.Println("  Press Ctrl+C to disconnect.")
	fmt.Println()

	// We need to call the connect logic inline. Reconstruct the flow.
	runConnectFromArgs(args)
}

func safeScanCommand(args []string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "\n  Fatal error: %v\n", r)
		}
	}()
	runScanCommand(args)
}

func interactiveScan(withE2E bool) {
	fmt.Println()
	if withE2E {
		fmt.Println("  ── DNS Scanner + E2E ────────────────────────────")
	} else {
		fmt.Println("  ── DNS Scanner ──────────────────────────────────")
	}
	fmt.Println()

	var args []string

	// Check if user has a config URI (makes E2E easier)
	if withE2E {
		configURI := promptDefault("  slipnet:// config (for domain+key, or blank to enter manually)", "")
		if configURI != "" && isSlipnetURI(configURI) {
			args = append(args, "--config", configURI)
		} else {
			domain := prompt("  Tunnel domain (e.g. t.example.com): ")
			if domain == "" {
				fmt.Println("  Domain is required.")
				waitExit()
				return
			}
			args = append(args, "--domain", domain)

			pubkey := prompt("  Server public key (hex): ")
			if pubkey == "" {
				fmt.Println("  Public key is required for E2E.")
				waitExit()
				return
			}
			args = append(args, "--e2e", "--pubkey", pubkey)

			tunnelMode := promptDefault("  Tunnel mode (dnstt/noizdns/vaydns)", "dnstt")
			switch strings.ToLower(strings.TrimSpace(tunnelMode)) {
			case "noizdns", "noiz":
				args = append(args, "--noizdns")
			case "vaydns", "vay":
				args = append(args, "--vaydns")
			}
		}
	} else {
		domain := prompt("  Tunnel domain (e.g. t.example.com): ")
		if domain == "" {
			fmt.Println("  Domain is required.")
			waitExit()
			return
		}
		args = append(args, "--domain", domain)
	}

	// IP source
	fmt.Println()
	fmt.Println("  IP source:")
	fmt.Println("    1) File (one IP per line)")
	fmt.Println("    2) Paste IPs")
	fmt.Println("    3) Built-in list")
	fmt.Println()
	ipChoice := prompt("  Select: ")

	switch ipChoice {
	case "1":
		filePath := prompt("  File path: ")
		filePath = strings.Trim(filePath, "\"' ") // Strip quotes from drag-and-drop
		if filePath == "" {
			fmt.Println("  File path is required.")
			waitExit()
			return
		}
		// Resolve relative paths
		if !filepath.IsAbs(filePath) {
			if cwd, err := os.Getwd(); err == nil {
				filePath = filepath.Join(cwd, filePath)
			}
		}
		args = append(args, "--ips", filePath)

	case "2":
		fmt.Println("  Paste IPs (one per line, empty line to finish):")
		var ips []string
		for {
			line := prompt("  ")
			if line == "" {
				break
			}
			// Handle comma-separated on single line
			for _, part := range strings.Split(line, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					ips = append(ips, part)
				}
			}
		}
		if len(ips) == 0 {
			fmt.Println("  No IPs entered.")
			waitExit()
			return
		}
		// Write to temp file
		tmpFile, err := os.CreateTemp("", "slipnet-ips-*.txt")
		if err != nil {
			fmt.Printf("  Error creating temp file: %v\n", err)
			waitExit()
			return
		}
		tmpFile.WriteString(strings.Join(ips, "\n"))
		tmpFile.Close()
		defer os.Remove(tmpFile.Name())
		args = append(args, "--ips", tmpFile.Name())

	case "3":
		// No --ips flag — runScanCommand falls back to built-in list

	default:
		fmt.Println("  Invalid choice.")
		waitExit()
		return
	}

	// Optional settings
	fmt.Println()
	concurrency := promptDefault("  Concurrency", "100")
	if v, _ := strconv.Atoi(concurrency); v > 0 {
		args = append(args, "--concurrency", concurrency)
	}
	timeout := promptDefault("  Timeout (ms)", "3000")
	if v, _ := strconv.Atoi(timeout); v > 0 {
		args = append(args, "--timeout", timeout)
	}
	qs := promptDefault("  Query size in bytes (blank = full capacity)", "")
	if v, err := strconv.Atoi(qs); err == nil && v >= 50 {
		args = append(args, "--max-query-size", qs)
	}
	if withE2E {
		e2eTimeout := promptDefault("  E2E timeout (ms)", "15000")
		if v, _ := strconv.Atoi(e2eTimeout); v > 0 {
			args = append(args, "--e2e-timeout", e2eTimeout)
		}
		e2eURL := promptDefault("  E2E test URL (blank = default, 'none' = tunnel-only)", "")
		if e2eURL != "" {
			args = append(args, "--e2e-url", e2eURL)
		}
		e2eOnly := promptDefault("  Show only E2E passed results? (y/N)", "n")
		if strings.HasPrefix(strings.ToLower(e2eOnly), "y") {
			args = append(args, "--e2e-results-only")
		}
	}

	fmt.Println()
	safeScanCommand(args)
	waitExit()
}

func interactiveQuickScan() {
	fmt.Println()
	fmt.Println("  ── Quick Scan (single IP) ───────────────────────")
	fmt.Println()

	domain := prompt("  Tunnel domain (e.g. t.example.com): ")
	if domain == "" {
		fmt.Println("  Domain is required.")
		waitExit()
		return
	}
	ip := prompt("  Resolver IP: ")
	if ip == "" {
		fmt.Println("  IP is required.")
		waitExit()
		return
	}

	args := []string{"--domain", domain, "--ip", ip}

	fmt.Println()
	safeScanCommand(args)
	waitExit()
}

func interactiveVerifyScan() {
	fmt.Println()
	fmt.Println("  ── Prism ─────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Requires SlipGate running on the server.")
	fmt.Println("  Sends multiple HMAC probes per resolver to verify")
	fmt.Println("  authenticity and filter unreliable resolvers.")
	fmt.Println()
	fmt.Println("  Requires the server public key (from slipnet:// config")
	fmt.Println("  or --pubkey) to authenticate responses.")
	fmt.Println()

	var args []string

	// Config URI or manual domain + pubkey
	configURI := promptDefault("  slipnet:// config (or blank to enter manually)", "")
	if configURI != "" && isSlipnetURI(configURI) {
		args = append(args, "--config", configURI, "--verify")
	} else {
		domain := prompt("  Tunnel domain (e.g. t.example.com): ")
		if domain == "" {
			fmt.Println("  Domain is required.")
			waitExit()
			return
		}
		pubkey := prompt("  Server public key (hex): ")
		if pubkey == "" {
			fmt.Println("  Public key is required for verify mode.")
			waitExit()
			return
		}
		args = append(args, "--domain", domain, "--pubkey", pubkey, "--verify")
	}

	// IP source
	fmt.Println()
	fmt.Println("  IP source:")
	fmt.Println("    1) File (one IP per line)")
	fmt.Println("    2) Paste IPs")
	fmt.Println("    3) Built-in list")
	fmt.Println()
	ipChoice := prompt("  Select: ")

	switch ipChoice {
	case "1":
		filePath := prompt("  File path: ")
		filePath = strings.Trim(filePath, "\"' ")
		if filePath == "" {
			fmt.Println("  File path is required.")
			waitExit()
			return
		}
		if !filepath.IsAbs(filePath) {
			if cwd, err := os.Getwd(); err == nil {
				filePath = filepath.Join(cwd, filePath)
			}
		}
		args = append(args, "--ips", filePath)

	case "2":
		fmt.Println("  Paste IPs (one per line, empty line to finish):")
		var ips []string
		for {
			line := prompt("  ")
			if line == "" {
				break
			}
			for _, part := range strings.Split(line, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					ips = append(ips, part)
				}
			}
		}
		if len(ips) == 0 {
			fmt.Println("  No IPs entered.")
			waitExit()
			return
		}
		tmpFile, err := os.CreateTemp("", "slipnet-ips-*.txt")
		if err != nil {
			fmt.Printf("  Error creating temp file: %v\n", err)
			waitExit()
			return
		}
		tmpFile.WriteString(strings.Join(ips, "\n"))
		tmpFile.Close()
		defer os.Remove(tmpFile.Name())
		args = append(args, "--ips", tmpFile.Name())

	case "3":
		// No --ips flag — runScanCommand falls back to built-in list

	default:
		fmt.Println("  Invalid choice.")
		waitExit()
		return
	}

	// Probe settings
	fmt.Println()
	fmt.Println("  Probe settings:")
	probes := promptDefault("  Probes per resolver (1-50)", "5")
	if v, err := strconv.Atoi(probes); err == nil && v > 0 {
		if v > 50 {
			probes = "50"
		}
		args = append(args, "--probes", probes)
	}
	threshold := promptDefault("  Pass threshold (min probes to pass)", "2")
	if v, err := strconv.Atoi(threshold); err == nil && v > 0 {
		if pv, _ := strconv.Atoi(probes); v > pv {
			threshold = probes
		}
		args = append(args, "--threshold", threshold)
	}

	// Response size
	fmt.Println()
	fmt.Println("  Response size: request the server to pad its DNS response.")
	fmt.Println("  Tests whether resolvers can handle larger responses.")
	fmt.Println("  Typical range: 200–1232 bytes (1232 = dnsflagday max UDP).")
	fmt.Println("  Leave blank for the server's default response size.")
	respSize := promptDefault("  Response size in bytes (200-1232, blank = default)", "")
	if v, err := strconv.Atoi(respSize); err == nil && v > 0 {
		args = append(args, "--response-size", respSize)
	}

	// Optional settings
	fmt.Println()
	concurrency := promptDefault("  Concurrency", "100")
	if v, _ := strconv.Atoi(concurrency); v > 0 {
		args = append(args, "--concurrency", concurrency)
	}
	timeout := promptDefault("  Timeout (ms)", "3000")
	if v, _ := strconv.Atoi(timeout); v > 0 {
		args = append(args, "--timeout", timeout)
	}

	// E2E option
	fmt.Println()
	fmt.Println("  Run E2E tunnel test on verified resolvers?")
	fmt.Println("  This starts a real tunnel through each verified resolver")
	fmt.Println("  and makes an HTTP request to confirm end-to-end connectivity.")
	e2eChoice := promptDefault("  Enable E2E (y/n)", "n")
	if strings.ToLower(e2eChoice) == "y" {
		args = append(args, "--e2e")
		e2eConcurrency := promptDefault("  E2E concurrency", "10")
		if v, _ := strconv.Atoi(e2eConcurrency); v > 0 {
			args = append(args, "--e2e-concurrency", e2eConcurrency)
		}
		e2eTimeout := promptDefault("  E2E timeout (ms)", "15000")
		if v, _ := strconv.Atoi(e2eTimeout); v > 0 {
			args = append(args, "--e2e-timeout", e2eTimeout)
		}
	}

	fmt.Println()
	safeScanCommand(args)
	waitExit()
}

func interactiveE2EOnly() {
	fmt.Println()
	fmt.Println("  ── E2E Test Only ────────────────────────────────")
	fmt.Println()
	fmt.Println("  Runs end-to-end tunnel tests directly on resolvers")
	fmt.Println("  without a DNS scan. Each resolver is tested by starting")
	fmt.Println("  a real tunnel and making an HTTP request through it.")
	fmt.Println()

	var args []string

	// Config URI or manual domain + pubkey
	configURI := promptDefault("  slipnet:// config (or blank to enter manually)", "")
	if configURI != "" && isSlipnetURI(configURI) {
		args = append(args, "--config", configURI, "--e2e-only")
	} else {
		domain := prompt("  Tunnel domain (e.g. t.example.com): ")
		if domain == "" {
			fmt.Println("  Domain is required.")
			waitExit()
			return
		}
		pubkey := prompt("  Server public key (hex): ")
		if pubkey == "" {
			fmt.Println("  Public key is required for E2E.")
			waitExit()
			return
		}
		args = append(args, "--domain", domain, "--pubkey", pubkey, "--e2e-only")

		tunnelMode := promptDefault("  Tunnel mode (dnstt/noizdns/vaydns)", "dnstt")
		switch strings.ToLower(strings.TrimSpace(tunnelMode)) {
		case "noizdns", "noiz":
			args = append(args, "--noizdns")
		case "vaydns", "vay":
			args = append(args, "--vaydns")
		}
	}

	// IP source
	fmt.Println()
	fmt.Println("  IP source:")
	fmt.Println("    1) File (one IP per line)")
	fmt.Println("    2) Paste IPs")
	fmt.Println("    3) Built-in list")
	fmt.Println()
	ipChoice := prompt("  Select: ")

	switch ipChoice {
	case "1":
		filePath := prompt("  File path: ")
		filePath = strings.Trim(filePath, "\"' ")
		if filePath == "" {
			fmt.Println("  File path is required.")
			waitExit()
			return
		}
		if !filepath.IsAbs(filePath) {
			if cwd, err := os.Getwd(); err == nil {
				filePath = filepath.Join(cwd, filePath)
			}
		}
		args = append(args, "--ips", filePath)

	case "2":
		fmt.Println("  Paste IPs (one per line, empty line to finish):")
		var ips []string
		for {
			line := prompt("  ")
			if line == "" {
				break
			}
			for _, part := range strings.Split(line, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					ips = append(ips, part)
				}
			}
		}
		if len(ips) == 0 {
			fmt.Println("  No IPs entered.")
			waitExit()
			return
		}
		tmpFile, err := os.CreateTemp("", "slipnet-ips-*.txt")
		if err != nil {
			fmt.Printf("  Error creating temp file: %v\n", err)
			waitExit()
			return
		}
		tmpFile.WriteString(strings.Join(ips, "\n"))
		tmpFile.Close()
		defer os.Remove(tmpFile.Name())
		args = append(args, "--ips", tmpFile.Name())

	case "3":
		// No --ips flag — runScanCommand falls back to built-in list

	default:
		fmt.Println("  Invalid choice.")
		waitExit()
		return
	}

	// Optional settings
	fmt.Println()
	concurrency := promptDefault("  Concurrency", "10")
	if v, _ := strconv.Atoi(concurrency); v > 0 {
		args = append(args, "--e2e-concurrency", concurrency)
	}
	timeout := promptDefault("  Timeout per resolver (ms)", "15000")
	if v, _ := strconv.Atoi(timeout); v > 0 {
		args = append(args, "--e2e-timeout", timeout)
	}
	qs := promptDefault("  Query size in bytes (blank = full capacity)", "")
	if v, err := strconv.Atoi(qs); err == nil && v >= 50 {
		args = append(args, "--max-query-size", qs)
	}
	e2eURL := promptDefault("  E2E test URL (blank = default, 'none' = tunnel-only)", "")
	if e2eURL != "" {
		args = append(args, "--e2e-url", e2eURL)
	}

	fmt.Println()
	safeScanCommand(args)
	waitExit()
}

// runConnectFromArgs runs the connect flow with the given CLI args.
// This avoids re-parsing os.Args and allows the interactive menu to
// call the connect logic directly.
func runConnectFromArgs(args []string) {
	var portOverride int
	var hostOverride string
	var dnsOverride string
	var utlsOverride string
	var forceDirectMode bool
	var querySize int
	var maxQnameLen int
	var vOpts vaydnsCLIOverrides
	var uriParts []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--dns", "-dns":
			if i+1 < len(args) {
				dnsOverride = args[i+1]
				i++
			}
		case "--port", "-port":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v > 0 && v <= 65535 {
					portOverride = v
				}
				i++
			}
		case "--host", "-host":
			if i+1 < len(args) {
				hostOverride = args[i+1]
				i++
			}
		case "--utls", "-utls":
			if i+1 < len(args) {
				utlsOverride = args[i+1]
				i++
			}
		case "--max-query-size":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v >= 50 {
					querySize = v
				}
				i++
			}
		case "--max-qname-len":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v >= 10 {
					maxQnameLen = v
				}
				i++
			}
		case "--vaydns-record-type":
			if i+1 < len(args) {
				vOpts.recordType = args[i+1]
				i++
			}
		case "--vaydns-rps":
			if i+1 < len(args) {
				if v, err := strconv.ParseFloat(args[i+1], 64); err == nil {
					vOpts.rps = v
					vOpts.rpsSet = true
				}
				i++
			}
		case "--vaydns-dnstt-compat":
			vOpts.dnsttCompat = true
			vOpts.dnsttCompatSet = true
		case "--vaydns-idle-timeout":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					vOpts.idleTimeout = v
					vOpts.idleTimeoutSet = true
				}
				i++
			}
		case "--vaydns-keepalive":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					vOpts.keepalive = v
					vOpts.keepaliveSet = true
				}
				i++
			}
		case "--vaydns-udp-timeout":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					vOpts.udpTimeout = v
					vOpts.udpTimeoutSet = true
				}
				i++
			}
		case "--vaydns-max-labels":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					vOpts.maxNumLabels = v
					vOpts.maxNumLabelsSet = true
				}
				i++
			}
		case "--vaydns-client-id-size":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil {
					vOpts.clientIdSize = v
					vOpts.clientIdSizeSet = true
				}
				i++
			}
		case "--direct", "-direct":
			forceDirectMode = true
		default:
			uriParts = append(uriParts, args[i])
		}
	}

	if len(uriParts) == 0 {
		fmt.Println("  No config URI provided.")
		return
	}

	uri := strings.TrimSpace(strings.Join(uriParts, ""))
	connectWithParams(uri, portOverride, hostOverride, dnsOverride, utlsOverride, forceDirectMode, querySize, maxQnameLen, "", 0, vOpts)
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

func isSlipnetURI(s string) bool {
	return strings.HasPrefix(s, "slipnet://") || strings.HasPrefix(s, "slipnet-enc://")
}

// formatResolverDisplay formats resolver strings for display.
// Input: "8.8.8.8:53:0,1.1.1.1:53:0" → "8.8.8.8:53, 1.1.1.1:53"
func formatResolverDisplay(resolvers string) string {
	parts := strings.Split(resolvers, ",")
	var out []string
	for _, r := range parts {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		// Strip the trailing ":0"/":1" (authoritative flag)
		fields := strings.Split(r, ":")
		if len(fields) >= 2 {
			out = append(out, fields[0]+":"+fields[1])
		} else {
			out = append(out, r)
		}
	}
	return strings.Join(out, ", ")
}
