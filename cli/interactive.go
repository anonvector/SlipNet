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
		fmt.Println("║  5) Help                                         ║")
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

// runConnectFromArgs runs the connect flow with the given CLI args.
// This avoids re-parsing os.Args and allows the interactive menu to
// call the connect logic directly.
func runConnectFromArgs(args []string) {
	var portOverride int
	var hostOverride string
	var dnsOverride string
	var utlsOverride string
	var forceDirectMode bool
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
	connectWithParams(uri, portOverride, hostOverride, dnsOverride, utlsOverride, forceDirectMode)
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
