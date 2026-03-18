package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
		fmt.Println("║  1) Connect (DNSTT / NoizDNS / Slipstream)       ║")
		fmt.Println("║  2) DNS Scanner                                  ║")
		fmt.Println("║  3) DNS Scanner + E2E Test                       ║")
		fmt.Println("║  4) Quick Scan (single IP)                       ║")
		fmt.Println("║  5) Verify Scanner (challenge-response)          ║")
		fmt.Println("║  6) Help                                         ║")
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
	fmt.Printf("  Domain:   %s\n", profile.Domain)
	fmt.Println()

	// Optional overrides
	portStr := promptDefault("  Local port", strconv.Itoa(profile.Port))
	if v, err := strconv.Atoi(portStr); err == nil && v > 0 {
		profile.Port = v
	}

	dnsOverride := promptDefault("  DNS override (blank = auto)", "")
	utlsOverride := promptDefault("  uTLS fingerprint (blank = random)", "")
	directStr := promptDefault("  Direct mode? (y/N)", "n")
	forceDirectMode := strings.HasPrefix(strings.ToLower(directStr), "y")

	fmt.Println()
	fmt.Println("  DNS query size (smaller = stealthier, slower):")
	fmt.Println("    0) Full capacity (fastest, default)")
	fmt.Println("    1) 100 bytes — large, good balance")
	fmt.Println("    2) 80 bytes  — medium, less conspicuous")
	fmt.Println("    3) 60 bytes  — small, stealthier")
	fmt.Println("    4) 50 bytes  — minimum, most stealthy")
	fmt.Println("    5) Custom")
	fmt.Println()
	qsChoice := promptDefault("  Select", "0")
	var querySize int
	switch qsChoice {
	case "0", "":
		// full capacity
	case "1":
		querySize = 100
	case "2":
		querySize = 80
	case "3":
		querySize = 60
	case "4":
		querySize = 50
	case "5":
		custom := prompt("  Enter size in bytes (>= 50): ")
		if v, err := strconv.Atoi(custom); err == nil && v >= 50 {
			querySize = v
		} else {
			fmt.Println("  Invalid value, using full capacity.")
		}
	default:
		// Try parsing as a direct number
		if v, err := strconv.Atoi(qsChoice); err == nil && v >= 50 {
			querySize = v
		}
	}

	var queryPadding int
	if querySize > 0 {
		fmt.Println()
		fmt.Println("  Random query padding (adds 0–N bytes to each query to vary size):")
		fmt.Println("    0) None (default)")
		fmt.Println("    1) 20 bytes  — 50–70 byte range when combined with size 50")
		fmt.Println("    2) Custom")
		fmt.Println()
		qpChoice := promptDefault("  Select", "0")
		switch qpChoice {
		case "0", "":
			// none
		case "1":
			queryPadding = 20
		case "2":
			custom := prompt("  Enter max padding bytes (> 0): ")
			if v, err := strconv.Atoi(custom); err == nil && v > 0 {
				queryPadding = v
			} else {
				fmt.Println("  Invalid value, no padding.")
			}
		default:
			if v, err := strconv.Atoi(qpChoice); err == nil && v > 0 {
				queryPadding = v
			}
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
		args = append(args, "--query-size", strconv.Itoa(querySize))
	}
	if queryPadding > 0 {
		args = append(args, "--query-padding", strconv.Itoa(queryPadding))
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

			noizdns := promptDefault("  NoizDNS mode? (y/N)", "n")
			if strings.HasPrefix(strings.ToLower(noizdns), "y") {
				args = append(args, "--noizdns")
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
	if withE2E {
		e2eTimeout := promptDefault("  E2E timeout (ms)", "15000")
		if v, _ := strconv.Atoi(e2eTimeout); v > 0 {
			args = append(args, "--e2e-timeout", e2eTimeout)
		}
	}

	fmt.Println()
	runScanCommand(args)
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
	runScanCommand(args)
	waitExit()
}

func interactiveVerifyScan() {
	fmt.Println()
	fmt.Println("  ── Verify Scanner (challenge-response) ──────────")
	fmt.Println()
	fmt.Println("  Requires SlipGate running on the server.")
	fmt.Println("  Repeats multiple rounds to filter unreliable resolvers.")
	fmt.Println()
	fmt.Println("  Requires the server public key (from slipnet:// config")
	fmt.Println("  or --pubkey) to authenticate responses.")
	fmt.Println("  Optionally request a specific response size to test")
	fmt.Println("  resolver packet size limits.")
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

	// Rounds
	roundsStr := promptDefault("  Rounds", "3")
	if v, _ := strconv.Atoi(roundsStr); v > 0 {
		args = append(args, "--rounds", roundsStr)
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

	// Response size
	respSize := promptDefault("  Response size in bytes (blank = server default)", "")
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

	fmt.Println()
	runScanCommand(args)
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
		case "--query-size":
			if i+1 < len(args) {
				v, err := strconv.Atoi(args[i+1])
				if err == nil && v >= 50 {
					querySize = v
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
	connectWithParams(uri, portOverride, hostOverride, dnsOverride, utlsOverride, forceDirectMode, querySize, 0)
}

func clearScreen() {
	if runtime.GOOS == "windows" {
		// Windows: use ANSI escape (works on Win10+ and Windows Terminal)
		fmt.Print("\033[2J\033[H")
	} else {
		fmt.Print("\033[2J\033[H")
	}
}

func isSlipnetURI(s string) bool {
	return strings.HasPrefix(s, "slipnet://") || strings.HasPrefix(s, "slipnet-enc://")
}
