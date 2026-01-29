#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SLIPSTREAM_DIR="${SLIPSTREAM_DIR:-"${ROOT_DIR}/../slipstream"}"
BUILD_DIR="${SLIPSTREAM_BUILD_DIR:-"${ROOT_DIR}/.interop/slipstream-build"}"
CERT_DIR="${CERT_DIR:-"${ROOT_DIR}/fixtures/certs"}"
RUN_DIR="${ROOT_DIR}/.interop/run-rust-client-$(date +%Y%m%d_%H%M%S)"

DNS_LISTEN_PORT="${DNS_LISTEN_PORT:-8853}"
PROXY_PORT="${PROXY_PORT:-5300}"
TCP_TARGET_PORT="${TCP_TARGET_PORT:-5201}"
CLIENT_TCP_PORT="${CLIENT_TCP_PORT:-7000}"
DOMAIN="${DOMAIN:-test.com}"
CLIENT_PAYLOAD="${CLIENT_PAYLOAD:-slipstream-rust}"
SOCKET_TIMEOUT="${SOCKET_TIMEOUT:-10}"

if [[ ! -d "${SLIPSTREAM_DIR}" ]]; then
  echo "Slipstream repo not found at ${SLIPSTREAM_DIR}. Set SLIPSTREAM_DIR to override." >&2
  exit 1
fi
if [[ ! -f "${CERT_DIR}/cert.pem" || ! -f "${CERT_DIR}/key.pem" ]]; then
  echo "Missing test certs in ${CERT_DIR}. Set CERT_DIR to override." >&2
  exit 1
fi

mkdir -p "${RUN_DIR}" "${ROOT_DIR}/.interop"

cleanup() {
  for pid in "${CLIENT_PID:-}" "${PROXY_PID:-}" "${SERVER_PID:-}" "${ECHO_PID:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT INT TERM HUP

if [[ ! -d "${BUILD_DIR}" ]]; then
  meson setup "${BUILD_DIR}" "${SLIPSTREAM_DIR}"
fi

picotls_libs=(
  "${BUILD_DIR}/subprojects/picoquic/libpicotls_core.a"
  "${BUILD_DIR}/subprojects/picoquic/libpicotls_openssl.a"
  "${BUILD_DIR}/subprojects/picoquic/libpicotls_minicrypto.a"
  "${BUILD_DIR}/subprojects/picoquic/libpicotls_fusion.a"
)
picotls_link_args=$(printf '"%s",' "${picotls_libs[@]}")
picotls_link_args="[${picotls_link_args%,}]"
meson configure "${BUILD_DIR}" \
  -Dc_link_args="${picotls_link_args}" \
  -Dcpp_link_args="${picotls_link_args}"

meson compile -C "${BUILD_DIR}"

SERVER_BIN="${BUILD_DIR}/slipstream-server"

if [[ ! -x "${SERVER_BIN}" ]]; then
  echo "Missing slipstream-server in ${BUILD_DIR}." >&2
  exit 1
fi

python3 "${ROOT_DIR}/scripts/interop/tcp_echo.py" \
  --listen "127.0.0.1:${TCP_TARGET_PORT}" \
  --log "${RUN_DIR}/tcp_echo.jsonl" \
  >"${RUN_DIR}/tcp_echo.log" 2>&1 &
ECHO_PID=$!

"${SERVER_BIN}" \
  --dns-listen-port "${DNS_LISTEN_PORT}" \
  --target-address "127.0.0.1:${TCP_TARGET_PORT}" \
  --domain "${DOMAIN}" \
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

SLIPSTREAM_BUILD_DIR="${BUILD_DIR}" cargo build -p slipstream-client

SLIPSTREAM_BUILD_DIR="${BUILD_DIR}" \
  "${ROOT_DIR}/target/debug/slipstream-client" \
  --tcp-listen-port "${CLIENT_TCP_PORT}" \
  --resolver "127.0.0.1:${PROXY_PORT}" \
  --domain "${DOMAIN}" \
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
