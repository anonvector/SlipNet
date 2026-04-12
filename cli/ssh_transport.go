package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// sshDial establishes the transport connection for SSH based on profile settings.
// Priority: WebSocket > HTTP CONNECT > direct. Each can optionally add TLS and/or payload.
func sshDial(profile *Profile) (net.Conn, error) {
	sshHost := profile.SSHHost
	if sshHost == "" {
		sshHost = profile.Domain
	}
	sshPort := profile.SSHPort
	if sshPort == 0 {
		sshPort = 22
	}

	if profile.SSHWsEnabled {
		return dialWebSocket(sshHost, sshPort, profile)
	}
	if profile.SSHHttpProxyHost != "" {
		return dialHTTPConnect(sshHost, sshPort, profile)
	}
	return dialDirect(sshHost, sshPort, profile)
}

// dialDirect connects directly to the SSH server with optional payload + TLS.
func dialDirect(host string, port int, profile *Profile) (net.Conn, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP connect to %s: %w", addr, err)
	}
	conn.(*net.TCPConn).SetNoDelay(true)

	// Send raw payload before TLS (DPI bypass)
	if profile.SSHPayload != "" {
		if err := sendPayload(conn, profile.SSHPayload, host, port); err != nil {
			conn.Close()
			return nil, err
		}
	}

	// Optional TLS wrapping
	if profile.SSHTlsEnabled {
		conn, err = wrapTLS(conn, host, port, profile.SSHTlsSni)
		if err != nil {
			return nil, err
		}
	}

	return conn, nil
}

// dialHTTPConnect tunnels through an HTTP CONNECT proxy, with optional TLS after.
func dialHTTPConnect(sshHost string, sshPort int, profile *Profile) (net.Conn, error) {
	proxyAddr := net.JoinHostPort(profile.SSHHttpProxyHost, fmt.Sprintf("%d", profile.SSHHttpProxyPort))
	conn, err := net.DialTimeout("tcp", proxyAddr, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP connect to proxy %s: %w", proxyAddr, err)
	}
	conn.(*net.TCPConn).SetNoDelay(true)

	// Build CONNECT request
	hostHeader := profile.SSHHttpProxyCustomHost
	if hostHeader == "" {
		hostHeader = net.JoinHostPort(sshHost, fmt.Sprintf("%d", sshPort))
	}
	connectTarget := net.JoinHostPort(sshHost, fmt.Sprintf("%d", sshPort))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n",
		connectTarget, hostHeader)

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}

	// Read response status line
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read proxy response: %w", err)
	}
	if !strings.Contains(statusLine, "200") {
		conn.Close()
		return nil, fmt.Errorf("proxy rejected CONNECT: %s", strings.TrimSpace(statusLine))
	}
	// Consume remaining headers
	for {
		line, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}

	// Wrap buffered reader back into a net.Conn
	if br.Buffered() > 0 {
		conn = &bufferedConn{Conn: conn, reader: br}
	}

	// Optional TLS after CONNECT tunnel
	if profile.SSHTlsEnabled {
		conn, err = wrapTLS(conn, sshHost, sshPort, profile.SSHTlsSni)
		if err != nil {
			return nil, err
		}
	}

	return conn, nil
}

// dialWebSocket tunnels through a WebSocket connection with optional TLS (wss://).
func dialWebSocket(sshHost string, sshPort int, profile *Profile) (net.Conn, error) {
	wsHost := sshHost
	wsPort := sshPort
	if profile.SSHWsUseTls && wsPort == 22 {
		wsPort = 443
	}

	addr := net.JoinHostPort(wsHost, fmt.Sprintf("%d", wsPort))
	conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("TCP connect to WS %s: %w", addr, err)
	}
	conn.(*net.TCPConn).SetNoDelay(true)

	// Optional TLS (wss://)
	if profile.SSHWsUseTls {
		sni := profile.SSHTlsSni
		if sni == "" {
			sni = wsHost
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true,
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("WS TLS handshake: %w", err)
		}
		conn = tlsConn
	}

	// WebSocket HTTP upgrade
	wsPath := profile.SSHWsPath
	if wsPath == "" {
		wsPath = "/"
	}
	hostHeader := profile.SSHWsCustomHost
	if hostHeader == "" {
		if wsPort == 443 || wsPort == 80 {
			hostHeader = wsHost
		} else {
			hostHeader = net.JoinHostPort(wsHost, fmt.Sprintf("%d", wsPort))
		}
	}

	wsKey := generateWSKey()
	upgradeReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		wsPath, hostHeader, wsKey)

	if _, err := conn.Write([]byte(upgradeReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send WS upgrade: %w", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read WS response: %w", err)
	}
	if !strings.Contains(statusLine, "101") {
		conn.Close()
		return nil, fmt.Errorf("WebSocket upgrade failed: %s", strings.TrimSpace(statusLine))
	}
	// Consume response headers
	for {
		line, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}

	return newWSConn(conn, br), nil
}

// wrapTLS wraps an existing connection in TLS with custom SNI.
func wrapTLS(conn net.Conn, host string, port int, sni string) (net.Conn, error) {
	if sni == "" {
		sni = host
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	return tlsConn, nil
}

// sendPayload writes raw bytes to the connection before SSH begins.
// Supports placeholders: [host], [port], [crlf], [cr], [lf].
func sendPayload(conn net.Conn, payload string, host string, port int) error {
	resolved := payload
	resolved = strings.ReplaceAll(resolved, "[host]", host)
	resolved = strings.ReplaceAll(resolved, "[port]", fmt.Sprintf("%d", port))
	resolved = strings.ReplaceAll(resolved, "[crlf]", "\r\n")
	resolved = strings.ReplaceAll(resolved, "[cr]", "\r")
	resolved = strings.ReplaceAll(resolved, "[lf]", "\n")
	_, err := conn.Write([]byte(resolved))
	return err
}

func generateWSKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// ── WebSocket net.Conn wrapper (RFC 6455) ─────────────────────────

const (
	wsOpContinuation = 0x0
	wsOpText         = 0x1
	wsOpBinary       = 0x2
	wsOpClose        = 0x8
	wsOpPing         = 0x9
	wsOpPong         = 0xA
)

// wsConn wraps a TCP connection with WebSocket binary framing.
type wsConn struct {
	raw    net.Conn
	reader *bufio.Reader
	mu     sync.Mutex // protects writes

	// read buffer
	buf    []byte
	bufOff int
	bufLen int
}

func newWSConn(conn net.Conn, br *bufio.Reader) *wsConn {
	return &wsConn{raw: conn, reader: br}
}

func (c *wsConn) Read(b []byte) (int, error) {
	for {
		// Return buffered frame data first
		if c.bufOff < c.bufLen {
			n := copy(b, c.buf[c.bufOff:c.bufLen])
			c.bufOff += n
			return n, nil
		}

		// Read next frame
		opcode, payload, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		switch opcode {
		case wsOpBinary, wsOpText, wsOpContinuation:
			if len(payload) == 0 {
				continue
			}
			c.buf = payload
			c.bufOff = 0
			c.bufLen = len(payload)
		case wsOpPing:
			c.writeFrame(wsOpPong, payload)
		case wsOpPong:
			// ignore
		case wsOpClose:
			return 0, io.EOF
		}
	}
}

func (c *wsConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if err := c.writeFrame(wsOpBinary, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsConn) Close() error                       { return c.raw.Close() }
func (c *wsConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *wsConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *wsConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

func (c *wsConn) readFrame() (int, []byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c.reader, hdr); err != nil {
		return 0, nil, err
	}
	opcode := int(hdr[0] & 0x0F)
	masked := (hdr[1] & 0x80) != 0
	payloadLen := uint64(hdr[1] & 0x7F)

	if payloadLen == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, ext); err != nil {
			return 0, nil, err
		}
		payloadLen = uint64(binary.BigEndian.Uint16(ext))
	} else if payloadLen == 127 {
		ext := make([]byte, 8)
		if _, err := io.ReadFull(c.reader, ext); err != nil {
			return 0, nil, err
		}
		payloadLen = binary.BigEndian.Uint64(ext)
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(c.reader, maskKey); err != nil {
			return 0, nil, err
		}
	}

	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}
	}

	return opcode, payload, nil
}

func (c *wsConn) writeFrame(opcode int, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	pLen := len(payload)
	// Header: FIN + opcode
	header := []byte{byte(0x80 | opcode)}

	// Mask bit (always set for client) + length
	switch {
	case pLen <= 125:
		header = append(header, byte(0x80|pLen))
	case pLen <= 65535:
		header = append(header, byte(0x80|126), byte(pLen>>8), byte(pLen&0xFF))
	default:
		header = append(header, byte(0x80|127))
		lenBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBytes, uint64(pLen))
		header = append(header, lenBytes...)
	}

	// Masking key
	mask := make([]byte, 4)
	rand.Read(mask)
	header = append(header, mask...)

	// Masked payload
	masked := make([]byte, pLen)
	for i := 0; i < pLen; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}

	// Write header + payload in one call
	frame := append(header, masked...)
	_, err := c.raw.Write(frame)
	return err
}

// ── Helper types ──────────────────────────────────────────────────

// bufferedConn wraps a net.Conn with a bufio.Reader for leftover data.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}
