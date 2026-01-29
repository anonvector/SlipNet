#!/bin/bash
#
# Deploy Slipstream Server
# Run this locally to upload and install on your server
#
# Usage: bash deploy.sh <user@server> <domain> [dns_resolver]
# Example: bash deploy.sh root@myserver.com tunnel.example.com 8.8.8.8
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SERVER="${1:-}"
DOMAIN="${2:-}"
DNS_RESOLVER="${3:-8.8.8.8}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "$SERVER" ] || [ -z "$DOMAIN" ]; then
    echo -e "${RED}Error: Missing required arguments${NC}"
    echo ""
    echo "Usage: bash deploy.sh <user@server> <domain> [dns_resolver]"
    echo ""
    echo "Arguments:"
    echo "  user@server   - SSH connection string (e.g., root@123.45.67.89)"
    echo "  domain        - Your tunnel domain (e.g., tunnel.example.com)"
    echo "  dns_resolver  - DNS resolver IP (default: 8.8.8.8)"
    echo ""
    echo "Examples:"
    echo "  bash deploy.sh root@myserver.com tunnel.example.com"
    echo "  bash deploy.sh ubuntu@123.45.67.89 t.mydomain.com 1.1.1.1"
    echo ""
    exit 1
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Deploying Slipstream Server${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Server: $SERVER"
echo "Domain: $DOMAIN"
echo "DNS Resolver: $DNS_RESOLVER"
echo ""

# Check required files exist
echo -e "${YELLOW}Checking local files...${NC}"
if [ ! -f "$SCRIPT_DIR/slipstream-server-v0.1.0-linux-x86_64" ]; then
    echo -e "${RED}Error: slipstream-server-v0.1.0-linux-x86_64 not found!${NC}"
    exit 1
fi
if [ ! -f "$SCRIPT_DIR/install-server.sh" ]; then
    echo -e "${RED}Error: install-server.sh not found!${NC}"
    exit 1
fi
echo -e "${GREEN}  All files found${NC}"
echo ""

# Upload files
echo -e "${YELLOW}Uploading files to server...${NC}"
scp -q "$SCRIPT_DIR/slipstream-server-v0.1.0-linux-x86_64" \
       "$SCRIPT_DIR/install-server.sh" \
       "$SERVER:/tmp/"
echo -e "${GREEN}  Files uploaded${NC}"
echo ""

# Run install script
echo -e "${YELLOW}Running installation on server...${NC}"
echo ""
ssh -t "$SERVER" "sudo bash /tmp/install-server.sh '$DOMAIN' '$DNS_RESOLVER'"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
