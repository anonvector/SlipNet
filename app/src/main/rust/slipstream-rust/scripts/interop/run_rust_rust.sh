#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CERT_DIR="${CERT_DIR:-"${ROOT_DIR}/fixtures/certs"}"
RUN_DIR="${ROOT_DIR}/.interop/run-rust-rust-$(date +%Y%m%d_%H%M%S)"

DNS_LISTEN_PORT="${DNS_LISTEN_PORT:-8853}"
PROXY_PORT="${PROXY_PORT:-5300}"
TCP_TARGET_PORT="${TCP_TARGET_PORT:-5201}"
CLIENT_TCP_PORT="${CLIENT_TCP_PORT:-7000}"
DOMAIN="${DOMAIN:-test.com}"
DOMAINS="${DOMAINS:-}"
CLIENT_DOMAIN="${CLIENT_DOMAIN:-}"
CLIENT_PAYLOAD="${CLIENT_PAYLOAD:-slipstream-rust}"
SOCKET_TIMEOUT="${SOCKET_TIMEOUT:-10}"

if [[ ! -f "${CERT_DIR}/cert.pem" || ! -f "${CERT_DIR}/key.pem" ]]; then
  echo "Missing test certs in ${CERT_DIR}. Set CERT_DIR to override." >&2
  exit 1
fi

mkdir -p "${RUN_DIR}" "${ROOT_DIR}/.interop"

sanitize_domain() {
  printf '%s' "$1" | tr -d '[:space:]'
}

server_domains=()
if [[ -n "${DOMAINS}" ]]; then
  if [[ "${DOMAINS}" == *","* ]]; then
    IFS=',' read -r -a server_domains <<< "${DOMAINS}"
  else
    read -r -a server_domains <<< "${DOMAINS}"
  fi
else
  server_domains=("${DOMAIN}")
fi

server_args=()
for domain in "${server_domains[@]}"; do
  domain="$(sanitize_domain "${domain}")"
  if [[ -n "${domain}" ]]; then
    server_args+=(--domain "${domain}")
  fi
done

if [[ "${#server_args[@]}" -eq 0 ]]; then
  echo "No server domains configured; set DOMAIN or DOMAINS." >&2
  exit 1
fi

if [[ -n "${CLIENT_DOMAIN}" ]]; then
  client_domain="$(sanitize_domain "${CLIENT_DOMAIN}")"
else
  client_domain="$(sanitize_domain "${server_domains[0]}")"
fi

cleanup() {
  for pid in "${CLIENT_PID:-}" "${PROXY_PID:-}" "${SERVER_PID:-}" "${ECHO_PID:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT INT TERM HUP

python3 "${ROOT_DIR}/scripts/interop/tcp_echo.py" \
  --listen "127.0.0.1:${TCP_TARGET_PORT}" \
  --log "${RUN_DIR}/tcp_echo.jsonl" \
  >"${RUN_DIR}/tcp_echo.log" 2>&1 &
ECHO_PID=$!

cargo build -p slipstream-server -p slipstream-client

"${ROOT_DIR}/target/debug/slipstream-server" \
  --dns-listen-port "${DNS_LISTEN_PORT}" \
  --target-address "127.0.0.1:${TCP_TARGET_PORT}" \
  "${server_args[@]}" \
  --cert "${CERT_DIR}/cert.pem" \
  --key "${CERT_DIR}/key.pem" \
  >"${RUN_DIR}/server.log" 2>&1 &
SERVER_PID=$!

python3 "${ROOT_DIR}/scripts/interop/udp_capture_proxy.py" \
  --listen "127.0.0.1:${PROXY_PORT}" \
  --upstream "127.0.0.1:${DNS_LISTEN_PORT}" \
  --log "${RUN_DIR}/dns_capture.jsonl" \
  >"${RUN_DIR}/udp_proxy.log" 2>&1 &
PROXY_PID=$!

"${ROOT_DIR}/target/debug/slipstream-client" \
  --tcp-listen-port "${CLIENT_TCP_PORT}" \
  --resolver "127.0.0.1:${PROXY_PORT}" \
  --domain "${client_domain}" \
  >"${RUN_DIR}/client.log" 2>&1 &
CLIENT_PID=$!

echo "Waiting for Rust client to accept connections..."
sleep 2
success=0
for _ in $(seq 1 5); do
  python3 - "${CLIENT_PAYLOAD}" "${CLIENT_TCP_PORT}" "${SOCKET_TIMEOUT}" <<'PY'
import socket
import sys
import time

payload = sys.argv[1].encode("utf-8")
port = int(sys.argv[2])
timeout = float(sys.argv[3])
try:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(payload)
        time.sleep(0.5)
except Exception:
    pass
PY
  sleep 2
  if [[ -s "${RUN_DIR}/tcp_echo.jsonl" ]] && grep -q '"event": "echo"' "${RUN_DIR}/tcp_echo.jsonl"; then
    success=1
    break
  fi
  sleep 1
done

if [[ "${success}" -ne 1 ]]; then
  echo "Echo validation failed; see logs in ${RUN_DIR}." >&2
  exit 1
fi

echo "Interop OK; logs in ${RUN_DIR}."
