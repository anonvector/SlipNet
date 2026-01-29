#!/bin/bash
#
# Slipstream Server Setup Script
# Sets up slipstream-server and high-performance Go proxy
#
# Usage: sudo bash install-server.sh <domain> [dns_resolver]
# Example: sudo bash install-server.sh tunnel.example.com 8.8.8.8
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() { echo -e "${CYAN}======== $1 ========${NC}"; }
print_step() { echo -e "${YELLOW}[$1/$TOTAL_STEPS] $2${NC}"; }
print_success() { echo -e "${GREEN}  ✓ $1${NC}"; }
print_error() { echo -e "${RED}  ✗ $1${NC}"; }

DOMAIN="${1:-}"
DNS_RESOLVER="${2:-8.8.8.8}"
PROXY_PORT="1080"
INSTALL_DIR="/opt/slipstream"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL_STEPS=9

print_header "Slipstream Server Setup"

if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Usage: sudo bash install-server.sh <domain> [dns_resolver]${NC}"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo)${NC}"
    exit 1
fi

echo -e "${YELLOW}Domain:${NC} $DOMAIN | ${YELLOW}DNS:${NC} $DNS_RESOLVER | ${YELLOW}Proxy:${NC} $PROXY_PORT"
echo ""

# Step 1: Install Go
print_step 1 "Installing dependencies..."
apt-get update -qq
apt-get install -y -qq golang-go openssl >/dev/null 2>&1 || apt-get install -y -qq golang openssl >/dev/null 2>&1
print_success "Dependencies installed"

# Step 2: Free port 53
print_step 2 "Freeing port 53..."
if ss -tlnp 2>/dev/null | grep -q ':53.*systemd-resolve'; then
    mkdir -p /etc/systemd/resolved.conf.d/
    echo -e "[Resolve]\nDNSStubListener=no" > /etc/systemd/resolved.conf.d/disable-stub.conf
    rm -f /etc/resolv.conf
    echo -e "nameserver ${DNS_RESOLVER}\nnameserver 8.8.8.8\nnameserver 1.1.1.1" > /etc/resolv.conf
    systemctl restart systemd-resolved 2>/dev/null || true
    print_success "Disabled systemd-resolved stub"
else
    print_success "Port 53 already free"
fi

# Step 3: Create directories
print_step 3 "Creating directories..."
mkdir -p "$INSTALL_DIR/certs"
print_success "Created $INSTALL_DIR"

# Step 4: Generate certificates
print_step 4 "Generating SSL certificates..."
if [ ! -f "$INSTALL_DIR/certs/cert.pem" ]; then
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$INSTALL_DIR/certs/key.pem" \
        -out "$INSTALL_DIR/certs/cert.pem" \
        -days 365 -nodes -subj "/CN=slipstream" 2>/dev/null
    print_success "Generated certificates"
else
    print_success "Certificates exist"
fi

# Step 5: Install slipstream-server
print_step 5 "Installing slipstream-server..."
if [ -f "$SCRIPT_DIR/slipstream-server-v0.1.0-linux-x86_64" ]; then
    cp "$SCRIPT_DIR/slipstream-server-v0.1.0-linux-x86_64" "$INSTALL_DIR/slipstream-server"
    chmod +x "$INSTALL_DIR/slipstream-server"
    print_success "Installed slipstream-server"
else
    print_error "slipstream-server binary not found!"
    exit 1
fi

# Step 6: Build Go proxy
print_step 6 "Building Go proxy..."
cat > /tmp/direct-proxy.go << 'EOF'
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
	bufferSize  = 65536
	dialTimeout = 10 * time.Second
	keepAlive   = 30 * time.Second
)

var bufferPool = sync.Pool{New: func() interface{} { b := make([]byte, bufferSize); return &b }}

func main() {
	port := "1080"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}
	lc := net.ListenConfig{KeepAlive: keepAlive}
	listener, err := lc.Listen(context.Background(), "tcp", ":"+port)
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}
	log.Printf("Direct proxy on port %s", port)
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigCh; log.Println("Shutting down..."); cancel(); listener.Close() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go handle(conn)
	}
}

func handle(client net.Conn) {
	defer client.Close()
	if tc, ok := client.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(keepAlive)
	}
	addrType := make([]byte, 1)
	if _, err := io.ReadFull(client, addrType); err != nil {
		return
	}
	var host string
	switch addrType[0] {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(client, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(client, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 0x03:
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
		return
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	dialer := net.Dialer{Timeout: dialTimeout, KeepAlive: keepAlive}
	target, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Printf("Connect %s:%d failed: %v", host, port, err)
		return
	}
	defer target.Close()
	if tc, ok := target.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	log.Printf("%s -> %s:%d", client.RemoteAddr(), host, port)
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		buf := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(buf)
		io.CopyBuffer(dst, src, *buf)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}
	go cp(target, client)
	go cp(client, target)
	wg.Wait()
}
EOF

cd /tmp && go build -ldflags="-s -w" -o "$INSTALL_DIR/direct-proxy" direct-proxy.go
chmod +x "$INSTALL_DIR/direct-proxy"
rm -f /tmp/direct-proxy.go
print_success "Built Go proxy"

# Step 7: Create services
print_step 7 "Creating systemd services..."
cat > /etc/systemd/system/direct-proxy.service << EOF
[Unit]
Description=Slipstream Direct Proxy
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/direct-proxy ${PROXY_PORT}
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/slipstream-server.service << EOF
[Unit]
Description=Slipstream DNS Tunnel Server
After=network.target direct-proxy.service
Requires=direct-proxy.service

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/slipstream-server -d ${DOMAIN} -a 127.0.0.1:${PROXY_PORT} -c ${INSTALL_DIR}/certs/cert.pem -k ${INSTALL_DIR}/certs/key.pem
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
print_success "Created services"

# Step 8: Start services
print_step 8 "Starting services..."
systemctl daemon-reload
systemctl enable direct-proxy slipstream-server >/dev/null 2>&1
systemctl start direct-proxy && sleep 1 && systemctl start slipstream-server
sleep 2
systemctl is-active --quiet direct-proxy && print_success "direct-proxy running" || print_error "direct-proxy failed"
systemctl is-active --quiet slipstream-server && print_success "slipstream-server running" || print_error "slipstream-server failed"

# Step 9: Configure firewall
print_step 9 "Configuring firewall..."
if command -v ufw &>/dev/null; then
    ufw allow 53/udp >/dev/null 2>&1 || true
    ufw allow 53/tcp >/dev/null 2>&1 || true
    print_success "Opened port 53"
fi

# Done
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
echo ""
print_header "Setup Complete!"
echo ""
echo -e "${GREEN}Services:${NC} slipstream-server (53) + direct-proxy ($PROXY_PORT)"
echo ""
echo -e "${YELLOW}DNS Records:${NC}"
echo "  NS:  ${DOMAIN}     → ns.${DOMAIN}"
echo "  A:   ns.${DOMAIN}  → ${SERVER_IP}"
echo ""
echo -e "${YELLOW}App Settings:${NC}"
echo "  Domain: ${DOMAIN}"
echo "  Resolver: 8.8.8.8:53"
echo ""
