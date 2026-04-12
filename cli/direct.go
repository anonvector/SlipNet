package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// connectSSHTunnel opens an SSH dynamic port forward (SOCKS5 proxy via SSH).
// Uses native Go SSH with support for TLS, HTTP CONNECT, WebSocket, and payload.
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
	printTransportInfo(profile)
	fmt.Printf("  SOCKS5:     %s\n", listenAddr)
	fmt.Println()

	if sshUser == "" {
		fmt.Println("  Error: SSH username is required")
		return
	}

	fmt.Println("  Starting SSH tunnel...")

	client, err := sshConnect(profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Error: %v\n", err)
		return
	}

	// Run SOCKS5 server in background
	go func() {
		if err := runSOCKS5Server(client, listenAddr, "", ""); err != nil {
			fmt.Fprintf(os.Stderr, "\n  SOCKS5 server error: %v\n", err)
		}
	}()

	if !waitForPort(context.Background(), listenAddr, 15*time.Second) {
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

	sshMonitorLoop(client, profile, listenAddr, func(c *ssh.Client) {
		go func() {
			if err := runSOCKS5Server(c, listenAddr, "", ""); err != nil {
				fmt.Fprintf(os.Stderr, "\n  SOCKS5 server error: %v\n", err)
			}
		}()
	})
}

// connectSOCKS5 connects to a remote SOCKS5 proxy via SSH port forwarding.
func connectSOCKS5(profile *Profile) {
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
	fmt.Printf("  Type:       Direct SOCKS5\n")
	fmt.Printf("  Server:     %s\n", sshHost)
	printTransportInfo(profile)
	fmt.Println()

	if sshUser == "" {
		fmt.Fprintln(os.Stderr, "  Error: SSH credentials required to reach SOCKS5 proxy.\n"+
			"  The server's SOCKS5 proxy listens on localhost only.\n"+
			"  An SSH tunnel is needed to forward traffic to it.\n"+
			"  Add SSH or SOCKS5 credentials to your config and re-export.")
		return
	}

	fmt.Printf("  Forwarding %s -> %s:1080 via SSH\n", listenAddr, sshHost)
	fmt.Println("  Starting SSH port forward...")

	client, err := sshConnect(profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Error: %v\n", err)
		return
	}

	// SSH local port forward: local -> remote:1080 (microsocks)
	go func() {
		if err := runPortForward(client, listenAddr, "127.0.0.1:1080"); err != nil {
			fmt.Fprintf(os.Stderr, "\n  Port forward error: %v\n", err)
		}
	}()

	if !waitForPort(context.Background(), listenAddr, 15*time.Second) {
		fmt.Println("  Warning: Port forward not ready yet")
	}

	fmt.Println()
	fmt.Printf("  Connected! SOCKS5 proxy available on %s\n", listenAddr)
	fmt.Println()
	fmt.Printf("  Or: curl --socks5-hostname %s https://ifconfig.me\n", listenAddr)
	fmt.Println()
	fmt.Println("  Press Ctrl+C to disconnect.")

	sshMonitorLoop(client, profile, listenAddr, func(c *ssh.Client) {
		go func() {
			if err := runPortForward(c, listenAddr, "127.0.0.1:1080"); err != nil {
				fmt.Fprintf(os.Stderr, "\n  Port forward error: %v\n", err)
			}
		}()
	})
}

// sshMonitorLoop monitors the SSH connection and auto-reconnects when it dies.
// onConnect is called after each successful (re)connection to start the server goroutine.
func sshMonitorLoop(client *ssh.Client, profile *Profile, listenAddr string, onConnect func(*ssh.Client)) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	reconnectDelay := 3 * time.Second
	waitCh := make(chan error, 1)
	go func() { waitCh <- client.Wait() }()

	for {
		select {
		case <-sigCh:
			fmt.Println("\n  Disconnecting...")
			client.Close()
			fmt.Println("  Done.")
			return
		case <-waitCh:
			fmt.Printf("\n  SSH connection lost, reconnecting in %v...\n", reconnectDelay)
			client.Close()
			time.Sleep(reconnectDelay)

			newClient, err := sshConnect(profile)
			if err != nil {
				fmt.Printf("  Reconnect failed: %v\n", err)
				// Keep retrying
				waitCh = make(chan error, 1)
				go func() {
					time.Sleep(reconnectDelay)
					waitCh <- fmt.Errorf("retry")
				}()
				continue
			}

			client = newClient
			onConnect(client)

			if !waitForPort(context.Background(), listenAddr, 10*time.Second) {
				fmt.Println("  Warning: proxy not ready after reconnect")
			}
			fmt.Println("  Reconnected!")

			waitCh = make(chan error, 1)
			go func() { waitCh <- client.Wait() }()
		}
	}
}

// runPortForward implements SSH local port forwarding (-L equivalent).
func runPortForward(client *ssh.Client, localAddr, remoteAddr string) error {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		return err
	}

	go func() {
		client.Wait()
		ln.Close()
	}()

	for {
		local, err := ln.Accept()
		if err != nil {
			return nil
		}
		go func() {
			defer local.Close()
			remote, err := client.Dial("tcp", remoteAddr)
			if err != nil {
				return
			}
			defer remote.Close()
			relay(local, remote)
		}()
	}
}

// printTransportInfo displays transport details for SSH connections.
func printTransportInfo(profile *Profile) {
	if profile.SSHWsEnabled {
		proto := "ws"
		if profile.SSHWsUseTls {
			proto = "wss"
		}
		fmt.Printf("  Transport:  WebSocket (%s://%s%s)\n", proto,
			profile.SSHHost, profile.SSHWsPath)
		if profile.SSHWsCustomHost != "" {
			fmt.Printf("  WS Host:    %s\n", profile.SSHWsCustomHost)
		}
	} else if profile.SSHHttpProxyHost != "" {
		fmt.Printf("  Proxy:      HTTP CONNECT via %s:%d\n",
			profile.SSHHttpProxyHost, profile.SSHHttpProxyPort)
		if profile.SSHHttpProxyCustomHost != "" {
			fmt.Printf("  Proxy Host: %s\n", profile.SSHHttpProxyCustomHost)
		}
	}
	if profile.SSHTlsEnabled {
		sni := profile.SSHTlsSni
		if sni == "" {
			sni = profile.SSHHost
		}
		fmt.Printf("  TLS:        enabled (SNI: %s)\n", sni)
	}
	if profile.SSHPayload != "" {
		fmt.Printf("  Payload:    %d bytes\n", len(profile.SSHPayload))
	}
}
