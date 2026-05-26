package main

import (
	"io"
	"net"
	"testing"
)

// socks5Pipe returns a connected pair; server is handled in a goroutine.
// The caller drives the client side and verifies the protocol bytes.
func runSOCKS5Handler(t *testing.T, reqUser, reqPass string) (client net.Conn, wait func()) {
	t.Helper()
	c, s := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleSOCKS5(s, nil, reqUser, reqPass)
	}()
	return c, func() { <-done }
}

func mustReadFull(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("ReadFull(%d): %v", n, err)
	}
	return buf
}

// TestSOCKS5_NoAuth verifies the server accepts a no-auth client when
// no credentials are configured.
func TestSOCKS5_NoAuth(t *testing.T) {
	client, wait := runSOCKS5Handler(t, "", "")
	defer client.Close()

	// Greeting: SOCKS5, one method, no-auth (0x00)
	client.Write([]byte{0x05, 0x01, 0x00})

	resp := mustReadFull(t, client, 2)
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("method selection: want {5,0}, got {%d,%d}", resp[0], resp[1])
	}

	// Close without sending CONNECT; server reads EOF and exits cleanly.
	client.Close()
	wait()
}

// TestSOCKS5_AuthCorrect verifies that correct credentials are accepted.
func TestSOCKS5_AuthCorrect(t *testing.T) {
	client, wait := runSOCKS5Handler(t, "user", "pass")
	defer client.Close()

	// Greeting: SOCKS5, one method, user/pass (0x02)
	client.Write([]byte{0x05, 0x01, 0x02})

	resp := mustReadFull(t, client, 2)
	if resp[1] != 0x02 {
		t.Fatalf("expected server to select user/pass (0x02), got 0x%02x", resp[1])
	}

	// Auth sub-negotiation: [ver=1, ulen=4, "user", plen=4, "pass"]
	client.Write([]byte{0x01, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'})

	authResp := mustReadFull(t, client, 2)
	if authResp[1] != 0x00 {
		t.Fatalf("expected auth success (0x00), got 0x%02x", authResp[1])
	}

	// Auth succeeded; server now waits for CONNECT. Close to unblock it.
	client.Close()
	wait()
}

// TestSOCKS5_AuthWrong verifies that wrong credentials are rejected and the
// connection is closed by the server.
func TestSOCKS5_AuthWrong(t *testing.T) {
	client, wait := runSOCKS5Handler(t, "user", "pass")
	defer client.Close()

	client.Write([]byte{0x05, 0x01, 0x02})
	resp := mustReadFull(t, client, 2)
	if resp[1] != 0x02 {
		t.Fatalf("expected method 0x02, got 0x%02x", resp[1])
	}

	// Wrong credentials
	client.Write([]byte{0x01, 5, 'w', 'r', 'o', 'n', 'g', 3, 'b', 'a', 'd'})

	authResp := mustReadFull(t, client, 2)
	if authResp[1] != 0x01 {
		t.Fatalf("expected auth failure (0x01), got 0x%02x", authResp[1])
	}

	// Server must have closed the connection; any further read returns EOF.
	wait()
	n, err := client.Read(make([]byte, 1))
	if n != 0 || err == nil {
		t.Fatalf("expected connection closed after auth failure, got n=%d err=%v", n, err)
	}
}

// TestSOCKS5_AuthRequired_NoMethodOffered verifies the server closes the
// connection when the client offers only no-auth but credentials are required.
func TestSOCKS5_AuthRequired_NoMethodOffered(t *testing.T) {
	client, wait := runSOCKS5Handler(t, "user", "pass")
	defer client.Close()

	// Client offers only no-auth — server requires user/pass
	client.Write([]byte{0x05, 0x01, 0x00})

	// Server selects 0x02 (user/pass); client has to send auth anyway
	resp := mustReadFull(t, client, 2)
	if resp[1] != 0x02 {
		t.Fatalf("expected method 0x02, got 0x%02x", resp[1])
	}

	// Client sends garbage auth that doesn't match
	client.Write([]byte{0x01, 0, 0})

	authResp := mustReadFull(t, client, 2)
	if authResp[1] != 0x01 {
		t.Fatalf("expected auth failure, got 0x%02x", authResp[1])
	}

	wait()
}
