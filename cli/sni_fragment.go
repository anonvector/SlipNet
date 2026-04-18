package main

import (
	"net"
	"time"
)

// fragmentConn wraps a net.Conn and fragments the first TLS Write (ClientHello).
// Go's tls.Client() writes the ClientHello through conn.Write(), so this wrapper
// intercepts that first write and splits it into multiple TCP segments.
type fragmentConn struct {
	net.Conn
	fragmented bool
	strategy   string
	delay      time.Duration
}

func (c *fragmentConn) Write(b []byte) (int, error) {
	// Detect TLS ClientHello: ContentType=0x16 (Handshake), then HandshakeType=0x01
	if !c.fragmented && len(b) > 5 && b[0] == 0x16 && b[5] == 0x01 {
		c.fragmented = true
		return fragmentWrite(c.Conn, b, c.strategy, c.delay)
	}
	return c.Conn.Write(b)
}

// fragmentWrite splits data according to strategy and sends each chunk with a delay.
func fragmentWrite(conn net.Conn, data []byte, strategy string, delay time.Duration) (int, error) {
	chunks := splitClientHello(data, strategy)
	for i, chunk := range chunks {
		if _, err := conn.Write(chunk); err != nil {
			return 0, err
		}
		if i < len(chunks)-1 && delay > 0 {
			time.Sleep(delay)
		}
	}
	return len(data), nil
}

// splitClientHello splits a TLS ClientHello according to the given strategy.
func splitClientHello(data []byte, strategy string) [][]byte {
	switch strategy {
	case "sni_split":
		offset := findSNIHostnameOffset(data)
		if offset > 0 && offset < len(data)-1 {
			// Find hostname length (2 bytes before hostname)
			hostnameLen := 0
			if offset >= 2 {
				hostnameLen = int(data[offset-2])<<8 | int(data[offset-1])
			}
			mid := offset
			if hostnameLen > 0 {
				mid = offset + hostnameLen/2
			} else {
				mid = offset + (len(data)-offset)/2
			}
			if mid <= 0 {
				mid = 1
			}
			if mid >= len(data) {
				mid = len(data) - 1
			}
			return [][]byte{data[:mid], data[mid:]}
		}
		// Fallback to half
		return splitHalf(data)
	case "half":
		return splitHalf(data)
	case "multi":
		return splitMulti(data, 24)
	default:
		return splitHalf(data)
	}
}

func splitHalf(data []byte) [][]byte {
	mid := len(data) / 2
	return [][]byte{data[:mid], data[mid:]}
}

func splitMulti(data []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

// findSNIHostnameOffset finds the byte offset where the SNI hostname data begins
// in a TLS ClientHello record.
func findSNIHostnameOffset(data []byte) int {
	if len(data) < 44 {
		return -1
	}

	pos := 5 + 4 // TLS record header (5) + handshake header (4)
	pos += 2     // client version
	pos += 32    // random

	if pos >= len(data) {
		return -1
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	if pos+2 > len(data) {
		return -1
	}
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen

	if pos+1 > len(data) {
		return -1
	}
	compMethodsLen := int(data[pos])
	pos += 1 + compMethodsLen

	if pos+2 > len(data) {
		return -1
	}
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	extensionsEnd := pos + extensionsLen

	// Iterate extensions to find SNI (type 0x0000)
	for pos+4 <= extensionsEnd && pos+4 <= len(data) {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extType == 0x0000 && extLen > 0 {
			// SNI extension: list_length(2) + name_type(1) + hostname_length(2) + hostname
			if pos+5 <= len(data) {
				hostnameStart := pos + 5
				if hostnameStart < len(data) {
					return hostnameStart
				}
			}
		}
		pos += extLen
	}

	return -1
}
