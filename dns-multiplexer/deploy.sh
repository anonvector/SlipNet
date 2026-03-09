#!/usr/bin/env bash
#
# DNS Multiplexer Deployment Script
# Sets up a DNS multiplexing middle proxy for DNSTT/NoizDNS on a datacenter VPS.
#
# Architecture:
#   Client (mobile ISP) --> This Proxy (datacenter) --> Multiple DNS resolvers --> dnstt-server
#
# The datacenter firewall is far less restrictive than mobile ISP firewalls.
# By multiplexing DNS queries across many resolvers, DPI detection becomes much harder.
#
# Usage:
#   bash <(curl -Ls https://raw.githubusercontent.com/anonvector/DNS-Multiplexer/main/deploy.sh)
#   bash deploy.sh                           # Interactive setup
#   bash deploy.sh --auto                    # Auto-install with defaults
#   bash deploy.sh --auto --port 5353        # Custom listen port
#   bash deploy.sh --uninstall               # Remove everything

set -e

# ─── Constants ───────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || pwd)"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dns-multiplexer"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_NAME="dns-multiplexer"
PROXY_SCRIPT="dns-mux.py"
RESOLVERS_FILE="resolvers.txt"
LOG_DIR="/var/log/dns-multiplexer"
REPO_RAW_URL="https://raw.githubusercontent.com/anonvector/DNS-Multiplexer/main"
SELF_INSTALL_PATH="/usr/local/bin/dns-mux"

# Defaults
LISTEN_PORT=53
LISTEN_ADDR="0.0.0.0"
MODE="round-robin"
ENABLE_TCP=true
ENABLE_COVER=true
ENABLE_HEALTH=true
ENABLE_STATS=true
COVER_MIN=5
COVER_MAX=15
ALSO_DEPLOY_DNSTT=false
ENABLE_DOH=false

# CLI flags
AUTO_MODE=false
UNINSTALL=false
CUSTOM_PORT=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m'

print_status()   { echo -e "${GREEN}[+]${NC} $1"; }
print_warning()  { echo -e "${YELLOW}[!]${NC} $1"; }
print_error()    { echo -e "${RED}[-]${NC} $1"; }
print_question() { echo -ne "${BLUE}[?]${NC} $1"; }
print_header()   { echo -e "\n${CYAN}═══ $1 ═══${NC}\n"; }

# ─── CLI Argument Parsing ────────────────────────────────────────────────────

parse_args() {
    # Quick commands that don't need full setup
    case "${1:-}" in
        --status|-s)    check_root; show_status; exit 0 ;;
        --restart)      check_root; systemctl restart "$SERVICE_NAME" && print_status "Restarted"; exit 0 ;;
        --stop)         check_root; systemctl stop "$SERVICE_NAME" && print_status "Stopped"; exit 0 ;;
        --start)        check_root; systemctl start "$SERVICE_NAME" && print_status "Started"; exit 0 ;;
        --logs)         exec tail -f "$LOG_DIR/dns-mux.log" ;;
        --scan)         shift; exec python3 "$INSTALL_DIR/$PROXY_SCRIPT" --scan "$@" ;;
    esac

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --auto|-a)      AUTO_MODE=true ;;
            --uninstall|-u) UNINSTALL=true ;;
            --port|-p)      shift; CUSTOM_PORT="$1" ;;
            --no-tcp)       ENABLE_TCP=false ;;
            --no-cover)     ENABLE_COVER=false ;;
            --no-health)    ENABLE_HEALTH=false ;;
            --no-stats)     ENABLE_STATS=false ;;
            --mode|-m)      shift; MODE="$1" ;;
            --doh)          ENABLE_DOH=true ;;
            --with-dnstt)   ALSO_DEPLOY_DNSTT=true ;;
            --help|-h)
                echo "Usage: dns-mux [COMMAND] [OPTIONS]"
                echo ""
                echo "Commands:"
                echo "  --status, -s       Show service status and recent logs"
                echo "  --restart          Restart the service"
                echo "  --stop             Stop the service"
                echo "  --start            Start the service"
                echo "  --logs             Follow live logs"
                echo "  --scan [opts]      Scan resolvers for tunnel compatibility"
                echo ""
                echo "Install options:"
                echo "  --auto, -a         Non-interactive install with defaults"
                echo "  --doh              Use DoH upstream (when outbound port 53 is blocked)"
                echo "  --port, -p PORT    Listen port (default: 53)"
                echo "  --mode, -m MODE    round-robin or random (default: round-robin)"
                echo "  --no-tcp           Disable TCP DNS proxy"
                echo "  --no-cover         Disable cover traffic"
                echo "  --no-health        Disable health checks"
                echo "  --no-stats         Disable stats logging"
                echo "  --with-dnstt       Also deploy dnstt-server (uses bundled binaries)"
                echo "  --uninstall, -u    Remove dns-multiplexer"
                echo "  --help, -h         Show this help"
                exit 0
                ;;
            *) print_error "Unknown option: $1"; exit 1 ;;
        esac
        shift
    done

    if [[ -n "$CUSTOM_PORT" ]]; then
        if ! [[ "$CUSTOM_PORT" =~ ^[0-9]+$ ]] || (( CUSTOM_PORT < 1 || CUSTOM_PORT > 65535 )); then
            print_error "Invalid port: $CUSTOM_PORT (must be 1-65535)"
            exit 1
        fi
        LISTEN_PORT="$CUSTOM_PORT"
    fi

    if [[ -n "$MODE" ]] && [[ "$MODE" != "round-robin" && "$MODE" != "random" ]]; then
        print_error "Invalid mode: $MODE (must be round-robin or random)"
        exit 1
    fi
}

# ─── Pre-flight Checks ──────────────────────────────────────────────────────

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
    elif [[ -f /etc/redhat-release ]]; then
        OS_ID="centos"
    else
        OS_ID="unknown"
    fi

    case "$OS_ID" in
        ubuntu|debian)   PKG_MGR="apt"    ;;
        fedora)          PKG_MGR="dnf"    ;;
        centos|rocky|rhel|almalinux) PKG_MGR="yum" ;;
        *)
            print_warning "Unknown OS: $OS_ID. Will try to continue."
            PKG_MGR="apt"
            ;;
    esac

    print_status "Detected OS: $OS_ID ($PKG_MGR)"
}

detect_arch() {
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64|amd64)  BINARY_SUFFIX="linux-amd64" ;;
        i386|i686)     BINARY_SUFFIX="linux-386"    ;;
        aarch64|arm64) BINARY_SUFFIX="linux-arm64"  ;;
        armv7l|armhf)  BINARY_SUFFIX="linux-arm"    ;;
        *)
            print_warning "Unknown arch: $ARCH"
            BINARY_SUFFIX="linux-amd64"
            ;;
    esac
    print_status "Architecture: $ARCH ($BINARY_SUFFIX)"
}

check_python3() {
    if command -v python3 &>/dev/null; then
        PYTHON_BIN="$(command -v python3)"
        PY_VERSION="$(python3 --version 2>&1)"
        print_status "Python3 found: $PY_VERSION"
    else
        print_warning "Python3 not found. Installing..."
        case "$PKG_MGR" in
            apt) apt-get update -qq && apt-get install -y -qq python3 ;;
            dnf) dnf install -y -q python3 ;;
            yum) yum install -y -q python3 ;;
        esac

        if ! command -v python3 &>/dev/null; then
            print_error "Failed to install Python3"
            exit 1
        fi
        PYTHON_BIN="$(command -v python3)"
        print_status "Python3 installed: $(python3 --version 2>&1)"
    fi
}

# ─── Firewall Configuration ─────────────────────────────────────────────────

configure_firewall() {
    print_status "Configuring firewall for port $LISTEN_PORT..."

    if command -v ufw &>/dev/null; then
        ufw allow "$LISTEN_PORT/udp" 2>/dev/null || true
        [[ "$ENABLE_TCP" == "true" ]] && ufw allow "$LISTEN_PORT/tcp" 2>/dev/null || true
        print_status "UFW rules added"
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port="$LISTEN_PORT/udp" 2>/dev/null || true
        [[ "$ENABLE_TCP" == "true" ]] && firewall-cmd --permanent --add-port="$LISTEN_PORT/tcp" 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        print_status "firewalld rules added"
    elif command -v iptables &>/dev/null; then
        iptables -C INPUT -p udp --dport "$LISTEN_PORT" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p udp --dport "$LISTEN_PORT" -j ACCEPT 2>/dev/null || true
        if [[ "$ENABLE_TCP" == "true" ]]; then
            iptables -C INPUT -p tcp --dport "$LISTEN_PORT" -j ACCEPT 2>/dev/null || \
                iptables -I INPUT -p tcp --dport "$LISTEN_PORT" -j ACCEPT 2>/dev/null || true
        fi
        if command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables.rules 2>/dev/null || true
        fi
        print_status "iptables rules added"
    else
        print_warning "No firewall detected. Make sure port $LISTEN_PORT is open."
    fi
}

# ─── Installation ────────────────────────────────────────────────────────────

install_proxy() {
    print_header "Installing DNS Multiplexer Proxy"

    # Create directories
    mkdir -p "$CONFIG_DIR" "$LOG_DIR"

    # Install proxy script (local copy or download from repo)
    if [[ -f "$SCRIPT_DIR/$PROXY_SCRIPT" ]]; then
        cp "$SCRIPT_DIR/$PROXY_SCRIPT" "$INSTALL_DIR/$PROXY_SCRIPT"
    else
        print_status "Downloading $PROXY_SCRIPT from repository..."
        curl -fsSL "$REPO_RAW_URL/$PROXY_SCRIPT" -o "$INSTALL_DIR/$PROXY_SCRIPT" || {
            print_error "Failed to download $PROXY_SCRIPT"
            exit 1
        }
    fi
    chmod +x "$INSTALL_DIR/$PROXY_SCRIPT"
    print_status "Installed proxy: $INSTALL_DIR/$PROXY_SCRIPT"

    # Install resolvers file (local copy, download, or generate default)
    if [[ -f "$SCRIPT_DIR/$RESOLVERS_FILE" ]]; then
        cp "$SCRIPT_DIR/$RESOLVERS_FILE" "$CONFIG_DIR/$RESOLVERS_FILE"
    elif curl -fsSL "$REPO_RAW_URL/$RESOLVERS_FILE" -o "$CONFIG_DIR/$RESOLVERS_FILE" 2>/dev/null; then
        true  # downloaded successfully
    else
        cat > "$CONFIG_DIR/$RESOLVERS_FILE" << 'RESOLVERS'
# DNS Multiplexer - Upstream Resolvers
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
4.2.2.1
4.2.2.2
RESOLVERS
    fi
    print_status "Resolvers config: $CONFIG_DIR/$RESOLVERS_FILE"

    # Install this script as a command
    if [[ ! -f "$SELF_INSTALL_PATH" ]] || [[ "$(realpath "$0" 2>/dev/null)" != "$(realpath "$SELF_INSTALL_PATH" 2>/dev/null)" ]]; then
        if [[ -f "$SCRIPT_DIR/deploy.sh" ]]; then
            cp "$SCRIPT_DIR/deploy.sh" "$SELF_INSTALL_PATH"
        elif [[ -f "$0" && "$0" != "bash" && "$0" != "-bash" ]]; then
            cp "$0" "$SELF_INSTALL_PATH"
        else
            curl -fsSL "$REPO_RAW_URL/deploy.sh" -o "$SELF_INSTALL_PATH" 2>/dev/null || true
        fi
        chmod +x "$SELF_INSTALL_PATH" 2>/dev/null
        if [[ -x "$SELF_INSTALL_PATH" ]]; then
            print_status "Installed command: dns-mux (run 'dns-mux --help' anytime)"
        fi
    fi

    # Install logrotate config
    if [[ -d /etc/logrotate.d ]]; then
        cat > /etc/logrotate.d/dns-multiplexer << 'LOGROTATE'
/var/log/dns-multiplexer/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
LOGROTATE
        print_status "Logrotate config installed"
    fi
}

install_dnstt_server() {
    if [[ "$ALSO_DEPLOY_DNSTT" != "true" ]]; then
        return
    fi

    print_header "Installing dnstt-server"
    detect_arch

    BINARY_NAME="dnstt-server-$BINARY_SUFFIX"

    # Try local paths first, then download from repo
    if [[ -f "$SCRIPT_DIR/bin/$BINARY_NAME" ]]; then
        BINARY_SRC="$SCRIPT_DIR/bin/$BINARY_NAME"
    elif [[ -f "$SCRIPT_DIR/../noizdns-deploy/bin/$BINARY_NAME" ]]; then
        BINARY_SRC="$SCRIPT_DIR/../noizdns-deploy/bin/$BINARY_NAME"
    else
        print_status "Downloading $BINARY_NAME from repository..."
        BINARY_SRC="$(mktemp)"
        if ! curl -fsSL "$REPO_RAW_URL/bin/$BINARY_NAME" -o "$BINARY_SRC"; then
            print_error "Failed to download $BINARY_NAME"
            rm -f "$BINARY_SRC"
            ALSO_DEPLOY_DNSTT=false
            return
        fi
    fi

    cp "$BINARY_SRC" "$INSTALL_DIR/dnstt-server"
    chmod +x "$INSTALL_DIR/dnstt-server"
    print_status "Installed: $INSTALL_DIR/dnstt-server"

    # Generate keys if needed
    if [[ ! -f "$CONFIG_DIR/server.key" ]]; then
        print_status "Generating keypair..."
        "$INSTALL_DIR/dnstt-server" -gen-key -privkey-file "$CONFIG_DIR/server.key" \
            -pubkey-file "$CONFIG_DIR/server.pub" 2>/dev/null || {
            print_warning "Key generation failed. You'll need to provide keys manually."
        }
    fi
}

# ─── Systemd Service ────────────────────────────────────────────────────────

create_service() {
    print_header "Creating systemd service"

    # Build command line arguments
    EXEC_ARGS="$INSTALL_DIR/$PROXY_SCRIPT"
    EXEC_ARGS+=" --listen $LISTEN_ADDR:$LISTEN_PORT"
    EXEC_ARGS+=" --mode $MODE"

    if [[ "$ENABLE_DOH" == "true" ]]; then
        EXEC_ARGS+=" --doh"
        # Only pass resolvers file if it contains DoH URLs, not bare IPs
        if grep -q "^https://" "$CONFIG_DIR/$RESOLVERS_FILE" 2>/dev/null; then
            EXEC_ARGS+=" --resolvers-file $CONFIG_DIR/$RESOLVERS_FILE"
        fi
        # Otherwise falls back to built-in DoH resolvers (dns.google, cloudflare, quad9, etc.)
    else
        EXEC_ARGS+=" --resolvers-file $CONFIG_DIR/$RESOLVERS_FILE"
    fi
    # auto-select is now on by default, no flag needed
    if [[ "$ENABLE_TCP" == "true" ]]; then
        EXEC_ARGS+=" --tcp"
    fi
    if [[ "$ENABLE_COVER" == "true" ]]; then
        EXEC_ARGS+=" --cover --cover-min $COVER_MIN --cover-max $COVER_MAX"
    fi
    if [[ "$ENABLE_HEALTH" == "true" ]]; then
        EXEC_ARGS+=" --health-check"
    fi
    if [[ "$ENABLE_STATS" == "true" ]]; then
        EXEC_ARGS+=" --stats"
    fi

    cat > "$SYSTEMD_DIR/$SERVICE_NAME.service" << EOF
[Unit]
Description=DNS Multiplexer Proxy
Documentation=https://github.com/anonvector/SlipNet
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PYTHON_BIN $EXEC_ARGS
Restart=always
RestartSec=5
StartLimitIntervalSec=300
StartLimitBurst=10
StandardOutput=append:$LOG_DIR/dns-mux.log
StandardError=append:$LOG_DIR/dns-mux.log
LimitNOFILE=65535

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR $CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" 2>/dev/null
    print_status "Service created: $SERVICE_NAME"

    # Optional: dnstt-server service
    if [[ "$ALSO_DEPLOY_DNSTT" == "true" && -f "$INSTALL_DIR/dnstt-server" ]]; then
        print_question "Enter tunnel domain (e.g., t.example.com): "
        read -r TUNNEL_DOMAIN

        if [[ -z "$TUNNEL_DOMAIN" ]]; then
            print_warning "No domain provided. Skipping dnstt-server service."
        else
            cat > "$SYSTEMD_DIR/dnstt-server.service" << DNSTTEOF
[Unit]
Description=DNSTT Server (NoizDNS)
After=network.target dns-multiplexer.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/dnstt-server -udp :5300 -privkey-file $CONFIG_DIR/server.key $TUNNEL_DOMAIN 127.0.0.1:1080
Restart=on-failure
RestartSec=5
StandardOutput=append:$LOG_DIR/dnstt-server.log
StandardError=append:$LOG_DIR/dnstt-server.log
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
DNSTTEOF
            systemctl daemon-reload
            systemctl enable dnstt-server 2>/dev/null
            print_status "dnstt-server service created"
        fi
    fi
}

# ─── Interactive Configuration ───────────────────────────────────────────────

interactive_config() {
    print_header "DNS Multiplexer Configuration"

    # Listen port
    print_question "Listen port [53]: "
    read -r input
    LISTEN_PORT="${input:-53}"

    # Distribution mode
    print_question "Distribution mode (round-robin/random) [round-robin]: "
    read -r input
    MODE="${input:-round-robin}"

    # TCP support
    print_question "Enable TCP DNS proxy? (y/n) [y]: "
    read -r input
    [[ "${input:-y}" == "n" ]] && ENABLE_TCP=false

    # Cover traffic
    print_question "Enable cover traffic? (y/n) [y]: "
    read -r input
    [[ "${input:-y}" == "n" ]] && ENABLE_COVER=false

    # Health checks
    print_question "Enable resolver health checks? (y/n) [y]: "
    read -r input
    [[ "${input:-y}" == "n" ]] && ENABLE_HEALTH=false

    # Stats
    print_question "Enable statistics logging? (y/n) [y]: "
    read -r input
    [[ "${input:-y}" == "n" ]] && ENABLE_STATS=false

    # Custom resolvers
    print_question "Use default resolvers list? (y/n) [y]: "
    read -r input
    if [[ "${input:-y}" == "n" ]]; then
        echo "Enter resolvers (one per line, empty line to finish):"
        CUSTOM_RESOLVERS=""
        while true; do
            read -r resolver
            [[ -z "$resolver" ]] && break
            CUSTOM_RESOLVERS+="$resolver"$'\n'
        done
        if [[ -n "$CUSTOM_RESOLVERS" ]]; then
            echo "$CUSTOM_RESOLVERS" > "$SCRIPT_DIR/custom_resolvers.txt"
            RESOLVERS_FILE="custom_resolvers.txt"
        fi
    fi

    # Deploy dnstt-server alongside
    print_question "Also deploy dnstt-server on this machine? (y/n) [n]: "
    read -r input
    [[ "${input:-n}" == "y" ]] && ALSO_DEPLOY_DNSTT=true

    echo ""
    print_status "Configuration:"
    echo "  Port:         $LISTEN_PORT"
    echo "  Mode:         $MODE"
    echo "  TCP:          $ENABLE_TCP"
    echo "  Cover:        $ENABLE_COVER"
    echo "  Health:       $ENABLE_HEALTH"
    echo "  Stats:        $ENABLE_STATS"
    echo "  dnstt-server: $ALSO_DEPLOY_DNSTT"
    echo ""
    print_question "Proceed with installation? (y/n) [y]: "
    read -r input
    if [[ "${input:-y}" == "n" ]]; then
        echo "Aborted."
        exit 0
    fi
}

# ─── Uninstall ───────────────────────────────────────────────────────────────

uninstall() {
    print_header "Uninstalling DNS Multiplexer"

    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "$SYSTEMD_DIR/$SERVICE_NAME.service"
    rm -f "$INSTALL_DIR/$PROXY_SCRIPT"
    rm -f "$SELF_INSTALL_PATH"

    # Also clean up dnstt-server if it was deployed alongside
    if systemctl is-active dnstt-server &>/dev/null || [[ -f "$SYSTEMD_DIR/dnstt-server.service" ]]; then
        systemctl stop dnstt-server 2>/dev/null || true
        systemctl disable dnstt-server 2>/dev/null || true
        rm -f "$SYSTEMD_DIR/dnstt-server.service"
        rm -f "$INSTALL_DIR/dnstt-server"
        print_status "dnstt-server service removed"
    fi

    rm -rf "$CONFIG_DIR"
    rm -rf "$LOG_DIR"
    systemctl daemon-reload

    print_status "DNS Multiplexer removed"
    exit 0
}

# ─── Status / Management ────────────────────────────────────────────────────

show_status() {
    echo ""
    print_header "Service Status"
    systemctl status "$SERVICE_NAME" --no-pager 2>/dev/null || echo "Service not running"

    echo ""
    print_header "Recent Logs"
    if [[ -f "$LOG_DIR/dns-mux.log" ]]; then
        tail -20 "$LOG_DIR/dns-mux.log"
    else
        echo "No logs yet"
    fi
}

get_public_ip() {
    local ip
    local services=(
        "https://api.ipify.org"
        "https://checkip.amazonaws.com"
        "https://ifconfig.me"
        "https://icanhazip.com"
        "https://ipinfo.io/ip"
    )
    for svc in "${services[@]}"; do
        ip="$(curl -4 -s --max-time 5 "$svc" 2>/dev/null | tr -d '[:space:]')"
        # Validate it looks like an IPv4 address
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return
        fi
    done
    # Fallback to local IP
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$ip"
        return
    fi
    echo "<YOUR_SERVER_IP>"
}

print_client_config() {
    local SERVER_IP
    SERVER_IP="$(get_public_ip)"

    print_header "Client Configuration"

    echo -e "${BOLD}Your DNS Multiplexer is running at:${NC}"
    echo -e "  ${GREEN}$SERVER_IP:$LISTEN_PORT${NC}"
    echo ""
    echo -e "${BOLD}To use with DNSTT/NoizDNS/SlipNet:${NC}"
    echo ""
    echo "  1. In your SlipNet profile, set the DNS resolver to:"
    echo -e "     ${CYAN}$SERVER_IP${NC}"
    echo ""
    echo "  2. Or with the CLI client:"
    echo -e "     ${CYAN}slipnet --dns $SERVER_IP slipnet://YOUR_PROFILE${NC}"
    echo ""
    echo "  3. Or with dnstt-client directly:"
    echo -e "     ${CYAN}dnstt-client -udp $SERVER_IP:$LISTEN_PORT -pubkey-file server.pub t.example.com 127.0.0.1:1080${NC}"
    echo ""
    echo -e "${BOLD}How it works:${NC}"
    echo "  Your client sends DNS queries to this proxy."
    local resolver_count
    resolver_count="$(grep -cv '^\s*#\|^\s*$' "$CONFIG_DIR/$RESOLVERS_FILE" 2>/dev/null || echo 'multiple')"
    echo "  The proxy multiplexes them across $resolver_count upstream resolvers."
    echo "  Datacenter firewalls are much less restrictive than mobile ISP firewalls."
    echo "  DPI systems see traffic distributed across many resolvers and paths."
    echo ""
    echo -e "${BOLD}Management:${NC}"
    echo "  dns-mux --status      Show status and logs"
    echo "  dns-mux --restart     Restart the service"
    echo "  dns-mux --stop        Stop the service"
    echo "  dns-mux --logs        Follow live logs"
    echo "  dns-mux --uninstall   Remove everything"
    echo "  Resolvers: $CONFIG_DIR/$RESOLVERS_FILE"
}

# ─── Stop conflicting services on port 53 ───────────────────────────────────

stop_port53_conflicts() {
    if [[ "$LISTEN_PORT" != "53" ]]; then
        return
    fi

    # Check if systemd-resolved is using port 53
    if systemctl is-active systemd-resolved &>/dev/null; then
        print_warning "systemd-resolved is running and may conflict with port 53"

        local do_disable="y"
        if [[ "$AUTO_MODE" != "true" ]]; then
            print_question "Disable systemd-resolved stub listener? (y/n) [y]: "
            read -r input
            do_disable="${input:-y}"
        fi

        if [[ "$do_disable" == "y" ]]; then
            # Disable stub listener but keep resolved running for local resolution
            mkdir -p /etc/systemd/resolved.conf.d
            cat > /etc/systemd/resolved.conf.d/no-stub.conf << 'RESOLVEDCONF'
[Resolve]
DNSStubListener=no
RESOLVEDCONF
            systemctl restart systemd-resolved 2>/dev/null || true

            # Fix /etc/resolv.conf: point to the non-stub resolved interface
            if [[ -L /etc/resolv.conf ]]; then
                ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
            fi
            print_status "systemd-resolved stub listener disabled"
        fi
    fi

    # Check for dnsmasq or other DNS services
    for svc in dnsmasq named bind9; do
        if systemctl is-active "$svc" &>/dev/null; then
            print_warning "$svc is running and may conflict with port 53"
            if [[ "$AUTO_MODE" == "true" ]]; then
                systemctl stop "$svc" 2>/dev/null || true
                print_status "Stopped $svc"
            else
                print_question "Stop $svc? (y/n) [y]: "
                read -r input
                if [[ "${input:-y}" != "n" ]]; then
                    systemctl stop "$svc" 2>/dev/null || true
                    print_status "Stopped $svc"
                fi
            fi
        fi
    done
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║         DNS Multiplexer for DNSTT/NoizDNS       ║"
    echo "║                                                  ║"
    echo "║  Middle proxy that distributes DNS queries       ║"
    echo "║  across multiple resolvers to bypass DPI.        ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"

    check_root

    if [[ "$UNINSTALL" == "true" ]]; then
        uninstall
    fi

    detect_os
    check_python3

    if [[ "$AUTO_MODE" != "true" ]]; then
        interactive_config
    fi

    stop_port53_conflicts
    install_proxy
    install_dnstt_server
    configure_firewall
    create_service

    # Start the service
    systemctl start "$SERVICE_NAME"
    print_status "Service started!"

    show_status
    print_client_config
}

main "$@"
