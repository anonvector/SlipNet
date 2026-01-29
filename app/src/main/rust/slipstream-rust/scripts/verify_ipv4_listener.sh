#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DNS_HOST="${DNS_HOST:-127.0.0.1}"
TCP_HOST="127.0.0.1"
DOMAIN="${DOMAIN:-test.example.com}"
CERT="${CERT:-${ROOT_DIR}/fixtures/certs/cert.pem}"
KEY="${KEY:-${ROOT_DIR}/fixtures/certs/key.pem}"
TARGET_ADDRESS="${TARGET_ADDRESS:-127.0.0.1:1}"
BUILD_PROFILE="${BUILD_PROFILE:-debug}"
KEEP_LOGS="${KEEP_LOGS:-0}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to run this script." >&2
  exit 1
fi

if command -v rg >/dev/null 2>&1; then
  MATCH_CMD=(rg -q --fixed-strings)
elif command -v grep >/dev/null 2>&1; then
  MATCH_CMD=(grep -q -F)
else
  echo "rg or grep is required to run this script." >&2
  exit 1
fi

if [ -z "${DNS_PORT:-}" ] || [ -z "${TCP_PORT:-}" ]; then
  read -r picked_dns picked_tcp < <(python3 - <<'PY'
import socket

def pick_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

def pick_tcp():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

print(f"{pick_udp()} {pick_tcp()}")
PY
  )
  DNS_PORT="${DNS_PORT:-${picked_dns}}"
  TCP_PORT="${TCP_PORT:-${picked_tcp}}"
fi

if [ ! -f "${CERT}" ]; then
  echo "Missing cert: ${CERT}" >&2
  exit 1
fi
if [ ! -f "${KEY}" ]; then
  echo "Missing key: ${KEY}" >&2
  exit 1
fi

build_args=(-p slipstream-server -p slipstream-client)
bin_dir="${ROOT_DIR}/target/debug"
if [ "${BUILD_PROFILE}" = "release" ]; then
  build_args+=(--release)
  bin_dir="${ROOT_DIR}/target/release"
fi

cargo build "${build_args[@]}"

SERVER_BIN="${SERVER_BIN:-${bin_dir}/slipstream-server}"
CLIENT_BIN="${CLIENT_BIN:-${bin_dir}/slipstream-client}"

if [ ! -x "${SERVER_BIN}" ]; then
  echo "Missing server binary: ${SERVER_BIN}" >&2
  exit 1
fi
if [ ! -x "${CLIENT_BIN}" ]; then
  echo "Missing client binary: ${CLIENT_BIN}" >&2
  exit 1
fi

LOG_DIR="$(mktemp -d)"

cleanup() {
  set +e
  if [ -n "${CLIENT_PID:-}" ]; then
    kill "${CLIENT_PID}" 2>/dev/null || true
    wait "${CLIENT_PID}" 2>/dev/null || true
  fi
  if [ -n "${SERVER_PID:-}" ]; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  if [ "${KEEP_LOGS}" = "1" ]; then
    echo "Logs kept at ${LOG_DIR}"
  else
    rm -rf "${LOG_DIR}"
  fi
}
trap cleanup EXIT

RUST_LOG=info "${SERVER_BIN}" \
  --dns-listen-host "${DNS_HOST}" \
  --dns-listen-port "${DNS_PORT}" \
  --target-address "${TARGET_ADDRESS}" \
  --cert "${CERT}" \
  --key "${KEY}" \
  --domain "${DOMAIN}" \
  >"${LOG_DIR}/server.log" 2>&1 &
SERVER_PID=$!

sleep 0.5
if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
  echo "server exited early" >&2
  cat "${LOG_DIR}/server.log" >&2
  exit 1
fi

RUST_LOG=info "${CLIENT_BIN}" \
  --resolver "${DNS_HOST}:${DNS_PORT}" \
  --domain "${DOMAIN}" \
  --cert "${CERT}" \
  --tcp-listen-host "${TCP_HOST}" \
  --tcp-listen-port "${TCP_PORT}" \
  >"${LOG_DIR}/client.log" 2>&1 &
CLIENT_PID=$!

sleep 0.5
if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
  echo "client exited early" >&2
  cat "${LOG_DIR}/client.log" >&2
  exit 1
fi

wait_for_log() {
  local file="$1"
  local pattern="$2"
  local timeout_secs="$3"
  local start
  start="$(date +%s)"
  while true; do
    if "${MATCH_CMD[@]}" "${pattern}" "${file}"; then
      return 0
    fi
    if ! kill -0 "${CLIENT_PID}" 2>/dev/null; then
      return 1
    fi
    if [ "$(( $(date +%s) - start ))" -ge "${timeout_secs}" ]; then
      return 1
    fi
    sleep 0.05
  done
}

if ! wait_for_log "${LOG_DIR}/client.log" "Listening on TCP port" 5; then
  echo "client did not start listening" >&2
  cat "${LOG_DIR}/client.log" >&2
  exit 1
fi

TCP_HOST="${TCP_HOST}" TCP_PORT="${TCP_PORT}" python3 - <<'PY'
import os
import socket
import time

host = os.environ["TCP_HOST"]
port = int(os.environ["TCP_PORT"])
s = socket.socket()
s.settimeout(1)
s.connect((host, port))
s.sendall(b"ping")
time.sleep(0.2)
s.close()
PY

if ! wait_for_log "${LOG_DIR}/client.log" "Connection ready" 12; then
  echo "connection not ready" >&2
  cat "${LOG_DIR}/client.log" >&2
  cat "${LOG_DIR}/server.log" >&2
  exit 1
fi

echo "ipv4 listener check: ok"
