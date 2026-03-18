package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func slipstreamBinaryName() string {
	if runtime.GOOS == "windows" {
		return "slipstream-client.exe"
	}
	return "slipstream-client"
}

// findSlipstreamBinary locates the slipstream-client binary:
// 1. Extract from embedded binary (if compiled with -tags embed_slipstream)
// 2. Same directory as slipnet binary
// 3. Current working directory
// 4. System PATH
func findSlipstreamBinary() (string, error) {
	// Try embedded binary first
	if path, err := extractEmbeddedSlipstream(); err == nil && path != "" {
		return path, nil
	}

	name := slipstreamBinaryName()

	if exePath, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exePath), name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}

	return "", fmt.Errorf(
		"slipstream-client binary not found.\n"+
			"  Place '%s' next to the slipnet binary, or add it to your PATH.\n"+
			"  Download it from the SlipNet releases page.", name)
}

// extractEmbeddedSlipstream extracts the embedded slipstream-client binary
// to a cache directory. Uses content hash so it's only written once per version.
func extractEmbeddedSlipstream() (string, error) {
	if len(embeddedSlipstream) == 0 {
		return "", nil
	}

	// Cache dir: ~/.cache/slipnet/ (Linux/macOS) or %LOCALAPPDATA%/slipnet/ (Windows)
	cacheDir := getCacheDir()
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", err
	}

	// Hash the binary content so we only extract once per version
	hash := sha256.Sum256(embeddedSlipstream)
	shortHash := hex.EncodeToString(hash[:8])
	name := fmt.Sprintf("slipstream-client-%s", shortHash)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}

	path := filepath.Join(cacheDir, name)

	// Already extracted?
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	// Write to temp then rename (atomic on same filesystem)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, embeddedSlipstream, 0755); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return "", err
	}

	return path, nil
}

func getCacheDir() string {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "slipnet")
		}
		return filepath.Join(os.TempDir(), "slipnet")
	}
	if d := os.Getenv("XDG_CACHE_HOME"); d != "" {
		return filepath.Join(d, "slipnet")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "slipnet")
}

// SlipstreamProcess manages a slipstream-client subprocess.
type SlipstreamProcess struct {
	cmd *exec.Cmd
}

// StartSlipstream spawns the slipstream-client binary.
func StartSlipstream(profile *Profile, listenHost string, listenPort int, querySize int) (*SlipstreamProcess, error) {
	binPath, err := findSlipstreamBinary()
	if err != nil {
		return nil, err
	}

	var args []string
	args = append(args, "--domain", profile.Domain)
	args = append(args, "--tcp-listen-host", listenHost)
	args = append(args, "--tcp-listen-port", fmt.Sprintf("%d", listenPort))

	for _, r := range strings.Split(profile.Resolvers, ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		parts := strings.Split(r, ":")
		host := parts[0]
		port := "53"
		authoritative := false
		if len(parts) >= 2 && parts[1] != "" {
			port = parts[1]
		}
		if len(parts) >= 3 && parts[2] == "1" {
			authoritative = true
		}
		addr := host + ":" + port
		if authoritative || profile.AuthMode {
			args = append(args, "--authoritative", addr)
		} else {
			args = append(args, "--resolver", addr)
		}
	}

	if profile.CC != "" {
		args = append(args, "--congestion-control", profile.CC)
	}
	if profile.KeepAlive > 0 {
		args = append(args, "--keep-alive-interval", fmt.Sprintf("%d", profile.KeepAlive))
	}
	if profile.GSO {
		args = append(args, "--gso")
	}
	if querySize > 0 {
		args = append(args, "--query-size", fmt.Sprintf("%d", querySize))
	}

	cmd := exec.Command(binPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start slipstream-client: %v", err)
	}
	return &SlipstreamProcess{cmd: cmd}, nil
}

func (p *SlipstreamProcess) Wait() error { return p.cmd.Wait() }

func (p *SlipstreamProcess) Stop() {
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	if runtime.GOOS == "windows" {
		p.cmd.Process.Kill()
	} else {
		p.cmd.Process.Signal(syscall.SIGTERM)
	}
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		p.cmd.Process.Kill()
	}
}

// connectSlipstream handles the Slipstream connection flow.
func connectSlipstream(profile *Profile, listenHost string, listenPort int, querySize int) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Printf("║          SlipNet CLI  %-25s  ║\n", version)
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Profile:    %s\n", profile.Name)
	fmt.Printf("  Type:       Slipstream (QUIC)\n")
	fmt.Printf("  Domain:     %s\n", profile.Domain)
	fmt.Printf("  Resolvers:  %s\n", profile.Resolvers)
	if profile.CC != "" {
		fmt.Printf("  CC:         %s\n", profile.CC)
	}
	if querySize > 0 {
		fmt.Printf("  Query Size: %d bytes\n", querySize)
	}

	listenAddr := fmt.Sprintf("%s:%d", listenHost, listenPort)
	fmt.Printf("  SOCKS5:     %s\n", listenAddr)
	fmt.Println()
	fmt.Println("  Starting Slipstream tunnel...")

	proc, err := StartSlipstream(profile, listenHost, listenPort, querySize)
	if err != nil {
		fmt.Printf("\n  Error: %v\n", err)
		return
	}

	if !waitForPort(listenAddr, 15*time.Second) {
		fmt.Println("  Warning: SOCKS5 proxy not ready yet (QUIC handshake may still be in progress)")
	}

	fmt.Println()
	fmt.Printf("  Connected! SOCKS5 proxy listening on %s\n", listenAddr)
	fmt.Println()
	fmt.Println("  Configure your apps to use:")
	fmt.Printf("    SOCKS5 proxy: %s\n", listenAddr)
	fmt.Println()
	fmt.Printf("  Or: curl --socks5-hostname %s https://ifconfig.me\n", listenAddr)
	fmt.Println()
	fmt.Println("  Press Ctrl+C to disconnect.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	doneCh := make(chan error, 1)
	go func() { doneCh <- proc.Wait() }()

	select {
	case <-sigCh:
		fmt.Println("\n  Disconnecting...")
		proc.Stop()
		fmt.Println("  Done.")
	case err := <-doneCh:
		if err != nil {
			fmt.Printf("\n  Slipstream exited: %v\n", err)
		} else {
			fmt.Println("\n  Slipstream exited.")
		}
	}
}
