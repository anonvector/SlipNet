package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshConnect establishes an SSH connection over the profile's transport
// and returns the connected client.
func sshConnect(profile *Profile) (*ssh.Client, error) {
	sshHost := profile.SSHHost
	if sshHost == "" {
		sshHost = profile.Domain
	}
	sshPort := profile.SSHPort
	if sshPort == 0 {
		sshPort = 22
	}

	conn, err := sshDial(profile)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	addr := net.JoinHostPort(sshHost, strconv.Itoa(sshPort))
	client, err := sshHandshakeOver(profile, conn, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return client, nil
}

// sshHandshakeOver performs the SSH handshake over an existing net.Conn.
// On success the returned client owns conn; on error the caller still owns it.
func sshHandshakeOver(profile *Profile, conn net.Conn, addr string) (*ssh.Client, error) {
	sshUser := profile.SSHUser
	if sshUser == "" {
		sshUser = profile.SOCKSUser
	}
	if sshUser == "" {
		return nil, fmt.Errorf("SSH username required (set SSH user/pass in profile)")
	}

	var auths []ssh.AuthMethod
	if profile.SSHPass != "" {
		auths = append(auths, ssh.Password(profile.SSHPass))
	}

	config := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, fmt.Errorf("SSH handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	go sshKeepAlive(client, 30*time.Second)
	return client, nil
}

// dnsSSHLayer is an SSH client + SOCKS5 server layered on top of a running
// DNS tunnel. The DNS tunnel listens on an internal loopback port; this
// layer dials that port, completes the SSH handshake, and exposes a real
// SOCKS5 server on the user-facing listenAddr.
type dnsSSHLayer struct {
	client *ssh.Client
	dead   chan struct{}
}

// Dead returns a channel that is closed when the underlying SSH connection
// terminates (so the caller can rebuild the whole stack).
func (l *dnsSSHLayer) Dead() <-chan struct{} { return l.dead }

// Close tears down the SSH client (which also stops the SOCKS5 listener).
func (l *dnsSSHLayer) Close() {
	if l.client != nil {
		l.client.Close()
	}
}

// startDNSSSHLayer waits for the tunnel's internal port to be ready, dials
// it, performs an SSH handshake, and starts a local SOCKS5 server on
// listenAddr that forwards through the SSH client.
func startDNSSSHLayer(profile *Profile, internalAddr, listenAddr string) (*dnsSSHLayer, error) {
	if !waitForPort(context.Background(), internalAddr, 15*time.Second) {
		return nil, fmt.Errorf("tunnel internal port %s not ready", internalAddr)
	}
	conn, err := net.DialTimeout("tcp", internalAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial tunnel: %w", err)
	}

	sshHost := profile.SSHHost
	if sshHost == "" {
		sshHost = profile.Domain
	}
	sshPort := profile.SSHPort
	if sshPort == 0 {
		sshPort = 22
	}
	addr := net.JoinHostPort(sshHost, strconv.Itoa(sshPort))

	client, err := sshHandshakeOver(profile, conn, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	layer := &dnsSSHLayer{client: client, dead: make(chan struct{})}
	go func() {
		client.Wait()
		close(layer.dead)
	}()
	go func() {
		// runSOCKS5Server returns nil when its listener is closed (which
		// happens automatically once client.Wait() fires).
		_ = runSOCKS5Server(client, listenAddr, "", "")
	}()
	return layer, nil
}

// sshKeepAlive sends periodic keep-alive requests to detect dead connections.
func sshKeepAlive(client *ssh.Client, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil {
			return
		}
	}
}

// runSOCKS5Server listens for SOCKS5 connections and forwards them through the SSH tunnel.
func runSOCKS5Server(client *ssh.Client, listenAddr string, socksUser, socksPass string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}

	go func() {
		// Close listener when SSH client dies
		client.Wait()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return nil // listener closed
		}
		go handleSOCKS5(conn, client, socksUser, socksPass)
	}
}

// handleSOCKS5 handles one SOCKS5 client connection.
func handleSOCKS5(conn net.Conn, sshClient *ssh.Client, reqUser, reqPass string) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Phase 1: Method negotiation
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return // not SOCKS5
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	if reqUser != "" {
		// Require username/password auth (method 0x02)
		conn.Write([]byte{0x05, 0x02})

		// Read auth request
		// +----+------+----------+------+----------+
		// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		// +----+------+----------+------+----------+
		authHdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, authHdr); err != nil {
			return
		}
		uname := make([]byte, authHdr[1])
		if _, err := io.ReadFull(conn, uname); err != nil {
			return
		}
		plenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, plenBuf); err != nil {
			return
		}
		passwd := make([]byte, plenBuf[0])
		if _, err := io.ReadFull(conn, passwd); err != nil {
			return
		}

		if string(uname) != reqUser || string(passwd) != reqPass {
			conn.Write([]byte{0x01, 0x01}) // auth failure
			return
		}
		conn.Write([]byte{0x01, 0x00}) // auth success
	} else {
		// No auth required (method 0x00)
		conn.Write([]byte{0x05, 0x00})
	}

	// Phase 2: Connection request
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHdr); err != nil {
		return
	}
	if reqHdr[1] != 0x01 { // only CONNECT
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // command not supported
		return
	}

	var targetHost string
	switch reqHdr[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		targetHost = net.IP(addr).String()
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		targetHost = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		targetHost = net.IP(addr).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // address type not supported
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	// Dial through SSH tunnel
	remote, err := sshClient.Dial("tcp", target)
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	defer remote.Close()

	// Success response
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Clear deadline for relay
	conn.SetDeadline(time.Time{})

	// Bidirectional relay
	relay(conn, remote)
}

// relay copies data bidirectionally between two connections.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		// Signal write-half close if possible
		type closeWriter interface{ CloseWrite() error }
		if cw, ok := dst.(closeWriter); ok {
			cw.CloseWrite()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
