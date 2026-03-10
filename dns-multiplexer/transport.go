package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	dnsBufferSize   = 4096
	upstreamTimeout = 5 * time.Second
	dohContentType  = "application/dns-message"
)

var dohClient = &http.Client{
	Timeout: upstreamTimeout,
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

func sendQueryUDP(data []byte, addr string, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(data); err != nil {
		return nil, err
	}
	buf := make([]byte, dnsBufferSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func sendQueryDoH(data []byte, url string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dohContentType)
	req.Header.Set("Accept", dohContentType)

	client := &http.Client{
		Timeout:   timeout,
		Transport: dohClient.Transport,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
