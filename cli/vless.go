package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"encoding/base64"
)

// parseVlessURI parses a standard vless:// URI into a Profile.
// Format: vless://uuid@server:port?type=ws&security=tls&path=/ws&host=domain&sni=domain#name
func parseVlessURI(uri string) (*Profile, error) {
	withoutScheme := strings.TrimPrefix(uri, "vless://")
	withoutScheme = strings.TrimPrefix(withoutScheme, "VLESS://")

	// Split fragment (profile name)
	profileName := "VLESS"
	if idx := strings.Index(withoutScheme, "#"); idx >= 0 {
		profileName = withoutScheme[idx+1:]
		withoutScheme = withoutScheme[:idx]
	}

	// Split userinfo@host:port?params
	atIdx := strings.Index(withoutScheme, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("invalid VLESS URI: missing UUID")
	}
	uuid := withoutScheme[:atIdx]
	afterAt := withoutScheme[atIdx+1:]

	queryIdx := strings.Index(afterAt, "?")
	hostPort := afterAt
	queryString := ""
	if queryIdx >= 0 {
		hostPort = afterAt[:queryIdx]
		queryString = afterAt[queryIdx+1:]
	}

	// Parse host:port
	colonIdx := strings.LastIndex(hostPort, ":")
	server := hostPort
	port := 443
	if colonIdx > 0 {
		server = hostPort[:colonIdx]
		if p, err := strconv.Atoi(hostPort[colonIdx+1:]); err == nil {
			port = p
		}
	}

	// Parse query params
	params := make(map[string]string)
	if queryString != "" {
		for _, param := range strings.Split(queryString, "&") {
			eqIdx := strings.Index(param, "=")
			if eqIdx > 0 {
				key := param[:eqIdx]
				value := param[eqIdx+1:]
				// Simple URL decode for common cases
				value = strings.ReplaceAll(value, "%2F", "/")
				value = strings.ReplaceAll(value, "%3A", ":")
				value = strings.ReplaceAll(value, "%20", " ")
				value = strings.ReplaceAll(value, "+", " ")
				params[key] = value
			}
		}
	}

	wsPath := "/"
	if v, ok := params["path"]; ok {
		wsPath = v
	}
	wsHost := server
	if v, ok := params["host"]; ok {
		wsHost = v
	}
	sni := wsHost
	if v, ok := params["sni"]; ok {
		sni = v
	}
	cdnIp := server
	if v, ok := params["cdn"]; ok {
		cdnIp = v
	}
	cdnPort := port
	if v, ok := params["cdn-port"]; ok {
		if p, err := strconv.Atoi(v); err == nil {
			cdnPort = p
		}
	}

	p := &Profile{
		TunnelType:          "vless",
		Name:                profileName,
		Domain:              wsHost,
		Host:                "127.0.0.1",
		Port:                10880,
		VlessUuid:           uuid,
		VlessWsPath:         wsPath,
		VlessCdnIp:          cdnIp,
		VlessCdnPort:        cdnPort,
		SniFragmentEnabled:  true,
		SniFragmentStrategy: "sni_split",
		SniFragmentDelayMs:  100,
	}
	if sni != wsHost {
		p.FakeSni = sni
	}

	return p, nil
}

// connectVless starts a VLESS tunnel through Cloudflare CDN with SNI fragmentation.
// It provides a local SOCKS5 proxy that tunnels through:
//
//	SOCKS5 -> TLS (fragmented) -> WebSocket -> VLESS -> CDN -> Server
func connectVless(profile *Profile) {
	listenAddr := fmt.Sprintf("%s:%d", profile.Host, profile.Port)

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════╗")
	fmt.Printf("║          SlipNet CLI  %-25s  ║\n", version)
	fmt.Println("╚══════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Profile:    %s\n", profile.Name)
	fmt.Printf("  Type:       VLESS (CDN)\n")
	fmt.Printf("  CDN:        %s:%d\n", profile.VlessCdnIp, profile.VlessCdnPort)
	fmt.Printf("  Domain:     %s\n", profile.Domain)
	fmt.Printf("  UUID:       %s...\n", profile.VlessUuid[:8])
	fmt.Printf("  WS Path:    %s\n", profile.VlessWsPath)
	if profile.SniFragmentEnabled {
		fmt.Printf("  Fragment:   %s (delay %dms)\n", profile.SniFragmentStrategy, profile.SniFragmentDelayMs)
	}
	if profile.FakeSni != "" {
		fmt.Printf("  Fake SNI:   %s\n", profile.FakeSni)
	}
	fmt.Printf("  SOCKS5:     %s\n", listenAddr)
	fmt.Println()

	if profile.VlessUuid == "" {
		fmt.Println("  Error: VLESS UUID is required")
		return
	}
	if profile.VlessCdnIp == "" {
		fmt.Println("  Error: CDN IP is required")
		return
	}

	uuid, err := parseVlessUUID(profile.VlessUuid)
	if err != nil {
		fmt.Printf("  Error: invalid UUID: %v\n", err)
		return
	}

	fmt.Println("  Starting VLESS tunnel...")

	// Start local SOCKS5 server
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Error: %v\n", err)
		return
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleVlessSocks5(conn, profile, uuid)
		}
	}()

	fmt.Println()
	fmt.Printf("  Connected! SOCKS5 proxy listening on %s\n", listenAddr)
	fmt.Println()
	fmt.Printf("  Or: curl --socks5-hostname %s https://ifconfig.me\n", listenAddr)
	fmt.Println()
	fmt.Println("  Press Ctrl+C to disconnect.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Println("\n  Disconnecting...")
	ln.Close()
	fmt.Println("  Done.")
}

// handleVlessSocks5 handles a single SOCKS5 connection and tunnels it through VLESS.
func handleVlessSocks5(client net.Conn, profile *Profile, uuid []byte) {
	defer client.Close()

	// SOCKS5 greeting
	buf := make([]byte, 258)
	n, err := client.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	// No auth
	client.Write([]byte{0x05, 0x00})

	// SOCKS5 request
	n, err = client.Read(buf)
	if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	atyp := buf[3]
	var destHost string
	var addrEnd int

	switch atyp {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		destHost = fmt.Sprintf("%d.%d.%d.%d", buf[4], buf[5], buf[6], buf[7])
		addrEnd = 8
	case 0x03: // Domain
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		destHost = string(buf[5 : 5+domainLen])
		addrEnd = 5 + domainLen
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		destHost = net.IP(buf[4:20]).String()
		addrEnd = 20
	default:
		return
	}

	destPort := int(buf[addrEnd])<<8 | int(buf[addrEnd+1])

	// Reply success
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Connect to CDN
	cdnAddr := fmt.Sprintf("%s:%d", profile.VlessCdnIp, profile.VlessCdnPort)
	rawConn, err := net.DialTimeout("tcp", cdnAddr, 30*time.Second)
	if err != nil {
		return
	}
	rawConn.(*net.TCPConn).SetNoDelay(true)

	// Optionally wrap in fragment conn
	var tlsUnderlay net.Conn = rawConn
	if profile.SniFragmentEnabled {
		tlsUnderlay = &fragmentConn{
			Conn:     rawConn,
			strategy: profile.SniFragmentStrategy,
			delay:    time.Duration(profile.SniFragmentDelayMs) * time.Millisecond,
		}
	}

	// TLS handshake
	sni := profile.Domain
	if profile.FakeSni != "" {
		sni = profile.FakeSni
	}
	tlsConn := tls.Client(tlsUnderlay, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return
	}

	// WebSocket upgrade
	wsPath := profile.VlessWsPath
	if wsPath == "" {
		wsPath = "/"
	}
	wsKey := generateVlessWSKey()
	upgradeReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		wsPath, profile.Domain, wsKey)
	if _, err := tlsConn.Write([]byte(upgradeReq)); err != nil {
		tlsConn.Close()
		return
	}

	br := bufio.NewReader(tlsConn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "101") {
		tlsConn.Close()
		return
	}
	// Consume response headers
	for {
		line, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}

	// Build VLESS request header
	vlessHeader := buildVlessHeader(uuid, destHost, destPort)

	// Send as WebSocket binary frame
	writeWSBinaryFrame(tlsConn, vlessHeader)

	// Read VLESS server response
	serverFrame, err := readWSFrame(br)
	if err != nil || len(serverFrame) < 2 {
		tlsConn.Close()
		return
	}
	// VLESS response: version(1) + addons_len(1) + [addons]
	addonsLen := int(serverFrame[1])
	respPayloadOff := 2 + addonsLen
	if respPayloadOff < len(serverFrame) {
		client.Write(serverFrame[respPayloadOff:])
	}

	// Bidirectional relay (client <-> WS-framed VLESS)
	var wg sync.WaitGroup
	wg.Add(2)

	// client -> VLESS (wrap in WS frames)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		for {
			n, err := client.Read(buf)
			if n > 0 {
				writeWSBinaryFrame(tlsConn, buf[:n])
			}
			if err != nil {
				break
			}
		}
	}()

	// VLESS -> client (unwrap WS frames)
	go func() {
		defer wg.Done()
		for {
			frame, err := readWSFrame(br)
			if err != nil {
				break
			}
			if len(frame) > 0 {
				if _, err := client.Write(frame); err != nil {
					break
				}
			}
		}
	}()

	wg.Wait()
	tlsConn.Close()
}

// buildVlessHeader constructs the VLESS request header.
func buildVlessHeader(uuid []byte, host string, port int) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, 0x00)    // version
	buf = append(buf, uuid...) // 16 bytes
	buf = append(buf, 0x00)    // addons length = 0
	buf = append(buf, 0x01)    // command = TCP

	buf = append(buf, byte(port>>8), byte(port&0xFF))

	// Address
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		buf = append(buf, 0x01) // IPv4
		buf = append(buf, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil && ip != nil {
		buf = append(buf, 0x03) // IPv6
		buf = append(buf, ip6...)
	} else {
		// Domain
		buf = append(buf, 0x02)           // domain
		buf = append(buf, byte(len(host))) // length
		buf = append(buf, []byte(host)...)
	}

	return buf
}

// ── WebSocket framing helpers for VLESS ──────────────────────────────

var vlessWSMu sync.Mutex

func writeWSBinaryFrame(conn net.Conn, payload []byte) error {
	vlessWSMu.Lock()
	defer vlessWSMu.Unlock()

	pLen := len(payload)
	header := []byte{0x82} // FIN + binary

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

	mask := make([]byte, 4)
	rand.Read(mask)
	header = append(header, mask...)

	masked := make([]byte, pLen)
	for i := 0; i < pLen; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}

	frame := append(header, masked...)
	_, err := conn.Write(frame)
	return err
}

func readWSFrame(br *bufio.Reader) ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, err
	}
	opcode := int(hdr[0] & 0x0F)
	masked := (hdr[1] & 0x80) != 0
	payloadLen := uint64(hdr[1] & 0x7F)

	if payloadLen == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(br, ext); err != nil {
			return nil, err
		}
		payloadLen = uint64(binary.BigEndian.Uint16(ext))
	} else if payloadLen == 127 {
		ext := make([]byte, 8)
		if _, err := io.ReadFull(br, ext); err != nil {
			return nil, err
		}
		payloadLen = binary.BigEndian.Uint64(ext)
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(br, maskKey); err != nil {
			return nil, err
		}
	}

	if payloadLen > 16*1024*1024 {
		return nil, fmt.Errorf("frame too large: %d", payloadLen)
	}

	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(br, payload); err != nil {
			return nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}
	}

	switch opcode {
	case 0x08: // close
		return nil, io.EOF
	case 0x09: // ping (ignore for now)
		return []byte{}, nil
	case 0x0A: // pong (ignore)
		return []byte{}, nil
	}

	return payload, nil
}

// ── Utility ──────────────────────────────────────────────────────────

func parseVlessUUID(s string) ([]byte, error) {
	h := strings.ReplaceAll(s, "-", "")
	if len(h) != 32 {
		return nil, fmt.Errorf("invalid UUID length: %d", len(h))
	}
	return hex.DecodeString(h)
}

func generateVlessWSKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
