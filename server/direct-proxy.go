package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	bufferSize     = 65536
	dialTimeout    = 10 * time.Second
	keepAlive      = 30 * time.Second
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, bufferSize)
		return &buf
	},
}

func main() {
	port := "1080"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	// Listen on dual-stack (IPv4 and IPv6)
	lc := net.ListenConfig{
		KeepAlive: keepAlive,
	}
	listener, err := lc.Listen(context.Background(), "tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("Direct proxy listening on port %s", port)

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}
		go handleConnection(conn)
	}
}

func handleConnection(client net.Conn) {
	defer client.Close()

	if tc, ok := client.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(keepAlive)
	}

	// Read address type
	addrType := make([]byte, 1)
	if _, err := io.ReadFull(client, addrType); err != nil {
		return
	}

	var host string

	switch addrType[0] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(client, addr); err != nil {
			return
		}
		host = net.IP(addr).String()

	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(client, addr); err != nil {
			return
		}
		host = net.IP(addr).String()

	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(client, lenBuf); err != nil {
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(client, domain); err != nil {
			return
		}
		host = string(domain)

	default:
		log.Printf("Unknown address type: %d", addrType[0])
		return
	}

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)

	// Connect to target with timeout
	dialer := net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAlive,
	}
	target, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Printf("Connect to %s:%d failed: %v", host, port, err)
		return
	}
	defer target.Close()

	if tc, ok := target.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	log.Printf("%s -> %s:%d", client.RemoteAddr(), host, port)

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	copy := func(dst, src net.Conn) {
		defer wg.Done()
		buf := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(buf)
		io.CopyBuffer(dst, src, *buf)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}

	go copy(target, client)
	go copy(client, target)

	wg.Wait()
}
