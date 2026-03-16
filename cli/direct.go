package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

// connectSSHTunnel opens an SSH dynamic port forward (SOCKS5 proxy via SSH).
// Equivalent to: ssh -D <local_port> -N -p <ssh_port> user@host
func connectSSHTunnel(profile *Profile) {
	sshHost := profile.SSHHost
	if sshHost == "" {
		sshHost = profile.Domain
	}
	sshPort := profile.SSHPort
	if sshPort == 0 {
		sshPort = 22
	}
	sshUser := profile.SSHUser
	if sshUser == "" {
		sshUser = profile.SOCKSUser
	}

	listenAddr := fmt.Sprintf("%s:%d", profile.Host, profile.Port)

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Printf("║          SlipNet CLI  %-25s  ║\n", version)
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Profile:    %s\n", profile.Name)
	fmt.Printf("  Type:       SSH Tunnel\n")
	fmt.Printf("  SSH Host:   %s:%d\n", sshHost, sshPort)
	fmt.Printf("  SSH User:   %s\n", sshUser)
	fmt.Printf("  SOCKS5:     %s\n", listenAddr)
	fmt.Println()

	if sshUser == "" {
		fmt.Println("  Error: SSH username is required")
		return
	}

	// Find ssh binary
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		fmt.Println("  Error: ssh binary not found in PATH")
		return
	}

	args := []string{
		"-D", listenAddr,
		"-N",                           // no remote command
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
		"-p", fmt.Sprintf("%d", sshPort),
	}

	// Use sshpass for password auth if available and password is set
	var cmd *exec.Cmd
	if profile.SSHPass != "" {
		sshpassBin, err := exec.LookPath("sshpass")
		if err == nil {
			// Use sshpass
			sshpassArgs := []string{"-p", profile.SSHPass, sshBin}
			sshpassArgs = append(sshpassArgs, args...)
			sshpassArgs = append(sshpassArgs, fmt.Sprintf("%s@%s", sshUser, sshHost))
			cmd = exec.Command(sshpassBin, sshpassArgs...)
		} else {
			fmt.Println("  Note: sshpass not found, SSH will prompt for password")
			args = append(args, fmt.Sprintf("%s@%s", sshUser, sshHost))
			cmd = exec.Command(sshBin, args...)
		}
	} else {
		args = append(args, fmt.Sprintf("%s@%s", sshUser, sshHost))
		cmd = exec.Command(sshBin, args...)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Println("  Starting SSH tunnel...")

	if err := cmd.Start(); err != nil {
		fmt.Printf("\n  Error: %v\n", err)
		return
	}

	if !waitForPort(listenAddr, 15*time.Second) {
		fmt.Println("  Warning: SOCKS5 proxy not ready yet (SSH handshake may still be in progress)")
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
	go func() { doneCh <- cmd.Wait() }()

	select {
	case <-sigCh:
		fmt.Println("\n  Disconnecting...")
		if runtime.GOOS == "windows" {
			cmd.Process.Kill()
		} else {
			cmd.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-doneCh:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
		}
		fmt.Println("  Done.")
	case err := <-doneCh:
		if err != nil {
			fmt.Printf("\n  SSH exited: %v\n", err)
		} else {
			fmt.Println("\n  SSH tunnel closed.")
		}
	}
}

// connectSOCKS5 connects to a remote SOCKS5 proxy and forwards local traffic.
// Opens a local SOCKS5 listener that relays through the remote server.
func connectSOCKS5(profile *Profile) {
	sshHost := profile.SSHHost
	if sshHost == "" {
		sshHost = profile.Domain
	}

	listenAddr := fmt.Sprintf("%s:%d", profile.Host, profile.Port)

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Printf("║          SlipNet CLI  %-25s  ║\n", version)
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Profile:    %s\n", profile.Name)
	fmt.Printf("  Type:       Direct SOCKS5\n")
	fmt.Printf("  Server:     %s\n", sshHost)
	fmt.Println()

	// For direct SOCKS5, we use SSH tunnel to the server's microsocks
	// since the SOCKS5 proxy is on 127.0.0.1:1080 (not exposed)
	sshPort := profile.SSHPort
	if sshPort == 0 {
		sshPort = 22
	}
	sshUser := profile.SSHUser
	if sshUser == "" {
		sshUser = profile.SOCKSUser
	}

	if sshUser == "" {
		fmt.Println("  Error: SSH credentials required to reach SOCKS5 proxy")
		fmt.Println("  The server's SOCKS5 proxy listens on localhost only.")
		fmt.Println("  An SSH tunnel is needed to forward traffic to it.")
		return
	}

	// SSH local port forward: local:port -> remote:1080 (microsocks)
	fmt.Printf("  Forwarding %s → %s:1080 via SSH\n", listenAddr, sshHost)

	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		fmt.Println("  Error: ssh binary not found in PATH")
		return
	}

	args := []string{
		"-L", fmt.Sprintf("%s:127.0.0.1:1080", listenAddr),
		"-N",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
		"-p", fmt.Sprintf("%d", sshPort),
	}

	var cmd *exec.Cmd
	if profile.SSHPass != "" {
		sshpassBin, err := exec.LookPath("sshpass")
		if err == nil {
			sshpassArgs := []string{"-p", profile.SSHPass, sshBin}
			sshpassArgs = append(sshpassArgs, args...)
			sshpassArgs = append(sshpassArgs, fmt.Sprintf("%s@%s", sshUser, sshHost))
			cmd = exec.Command(sshpassBin, sshpassArgs...)
		} else {
			fmt.Println("  Note: sshpass not found, SSH will prompt for password")
			args = append(args, fmt.Sprintf("%s@%s", sshUser, sshHost))
			cmd = exec.Command(sshBin, args...)
		}
	} else {
		args = append(args, fmt.Sprintf("%s@%s", sshUser, sshHost))
		cmd = exec.Command(sshBin, args...)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Println("  Starting SSH port forward...")

	if err := cmd.Start(); err != nil {
		fmt.Printf("\n  Error: %v\n", err)
		return
	}

	if !waitForPort(listenAddr, 15*time.Second) {
		fmt.Println("  Warning: Port forward not ready yet")
	}

	fmt.Println()
	fmt.Printf("  Connected! SOCKS5 proxy available on %s\n", listenAddr)
	fmt.Println()
	fmt.Printf("  Or: curl --socks5-hostname %s https://ifconfig.me\n", listenAddr)
	fmt.Println()
	fmt.Println("  Press Ctrl+C to disconnect.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	doneCh := make(chan error, 1)
	go func() { doneCh <- cmd.Wait() }()

	select {
	case <-sigCh:
		fmt.Println("\n  Disconnecting...")
		if runtime.GOOS == "windows" {
			cmd.Process.Kill()
		} else {
			cmd.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-doneCh:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
		}
		fmt.Println("  Done.")
	case err := <-doneCh:
		if err != nil {
			fmt.Printf("\n  SSH exited: %v\n", err)
		} else {
			fmt.Println("\n  Connection closed.")
		}
	}
}
