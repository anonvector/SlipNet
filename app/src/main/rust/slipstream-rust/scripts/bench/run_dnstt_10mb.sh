#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DNSTT_DIR="${DNSTT_DIR:-"${ROOT_DIR}/../dnstt"}"
DNSTT_BUILD_DIR="${DNSTT_BUILD_DIR:-"${ROOT_DIR}/.interop/dnstt-build"}"
RUN_DIR="${ROOT_DIR}/.interop/bench-dnstt-$(date +%Y%m%d_%H%M%S)"
KEY_DIR="${RUN_DIR}/keys"

DNS_LISTEN_PORT="${DNS_LISTEN_PORT:-8853}"
TCP_TARGET_PORT="${TCP_TARGET_PORT:-5201}"
CLIENT_TCP_PORT="${CLIENT_TCP_PORT:-7000}"
DOMAIN="${DOMAIN:-test.com}"
SOCKET_TIMEOUT="${SOCKET_TIMEOUT:-30}"
TRANSFER_BYTES="${TRANSFER_BYTES:-10485760}"
CHUNK_SIZE="${CHUNK_SIZE:-16384}"
RUN_EXFIL="${RUN_EXFIL:-1}"
RUN_DOWNLOAD="${RUN_DOWNLOAD:-1}"
TCP_LINGER_SECS="${TCP_LINGER_SECS:-5}"
RUNS="${RUNS:-1}"
NETEM_IFACE="${NETEM_IFACE:-lo}"
NETEM_DELAY_MS="${NETEM_DELAY_MS:-}"
NETEM_JITTER_MS="${NETEM_JITTER_MS:-}"
NETEM_DIST="${NETEM_DIST:-normal}"
NETEM_SUDO="${NETEM_SUDO:-1}"
NETEM_ACTIVE=0
PROXY_DELAY_MS="${PROXY_DELAY_MS:-}"
PROXY_JITTER_MS="${PROXY_JITTER_MS:-}"
PROXY_DIST="${PROXY_DIST:-normal}"
PROXY_PORT="${PROXY_PORT:-}"

DNSTT_SERVER_BIN="${DNSTT_SERVER_BIN:-"${DNSTT_BUILD_DIR}/dnstt-server"}"
DNSTT_CLIENT_BIN="${DNSTT_CLIENT_BIN:-"${DNSTT_BUILD_DIR}/dnstt-client"}"

if [[ ! -d "${DNSTT_DIR}" ]]; then
  echo "dnstt repo not found at ${DNSTT_DIR}. Set DNSTT_DIR to override." >&2
  exit 1
fi

mkdir -p "${RUN_DIR}" "${ROOT_DIR}/.interop" "${DNSTT_BUILD_DIR}"

cleanup_pids() {
  for pid in "${CLIENT_PID:-}" "${SERVER_PID:-}" "${TARGET_PID:-}" "${PROXY_PID:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  CLIENT_PID=""
  SERVER_PID=""
  TARGET_PID=""
  PROXY_PID=""
}

setup_netem() {
  if [[ -z "${NETEM_DELAY_MS}" ]]; then
    return
  fi
  if ! command -v tc >/dev/null 2>&1; then
    echo "tc not found; install iproute2 or unset NETEM_DELAY_MS." >&2
    exit 1
  fi

  local args=(qdisc replace dev "${NETEM_IFACE}" root netem delay "${NETEM_DELAY_MS}ms")
  if [[ -n "${NETEM_JITTER_MS}" ]]; then
    args+=("${NETEM_JITTER_MS}ms" distribution "${NETEM_DIST}")
  fi

  echo "Applying netem on ${NETEM_IFACE}: delay ${NETEM_DELAY_MS}ms${NETEM_JITTER_MS:+ jitter ${NETEM_JITTER_MS}ms}." >&2
  if [[ "$(id -u)" -eq 0 ]]; then
    tc "${args[@]}"
  else
    if [[ "${NETEM_SUDO}" == "1" ]]; then
      sudo -n tc "${args[@]}" || {
        echo "Failed to apply netem; re-run with sudo or set NETEM_SUDO=0." >&2
        exit 1
      }
    else
      echo "NETEM requires root; re-run with sudo or set NETEM_SUDO=1." >&2
      exit 1
    fi
  fi
  NETEM_ACTIVE=1
}

cleanup_netem() {
  if [[ "${NETEM_ACTIVE}" != "1" ]]; then
    return
  fi
  local args=(qdisc del dev "${NETEM_IFACE}" root)
  if [[ "$(id -u)" -eq 0 ]]; then
    tc "${args[@]}" || true
  else
    if [[ "${NETEM_SUDO}" == "1" ]]; then
      sudo -n tc "${args[@]}" || true
    fi
  fi
}

cleanup() {
  cleanup_pids
  cleanup_netem
}
trap cleanup EXIT INT TERM HUP

e2e_report() {
  local label="$1"
  local start_log="$2"
  local end_log="$3"
  local bytes="$4"
  python3 - "$start_log" "$end_log" "$bytes" "$label" <<'PY'
import json
import sys

start_path, end_path, bytes_s, label = sys.argv[1:5]

def load_done(path: str):
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event") == "done":
                return event
    return None

start = load_done(start_path)
end = load_done(end_path)
if not start or not end:
    print(f"{label}: missing timing data")
    raise SystemExit(0)
start_ts = start.get("first_payload_ts")
end_ts = end.get("last_payload_ts")
if start_ts is None or end_ts is None:
    print(f"{label}: missing payload timestamps")
    raise SystemExit(0)
elapsed = end_ts - start_ts
if elapsed <= 0:
    print(f"{label}: invalid timing window secs={elapsed:.6f}")
    raise SystemExit(0)
bytes_val = int(bytes_s)
mib = bytes_val / (1024 * 1024)
mib_s = mib / elapsed
print(f"{label}: bytes={bytes_val} secs={elapsed:.3f} MiB/s={mib_s:.2f}")
PY
}

if [[ ! -x "${DNSTT_SERVER_BIN}" || ! -x "${DNSTT_CLIENT_BIN}" ]]; then
  if ! command -v go >/dev/null 2>&1; then
    echo "go is required to build dnstt." >&2
    exit 1
  fi
  pushd "${DNSTT_DIR}" >/dev/null
  go build -o "${DNSTT_SERVER_BIN}" ./dnstt-server
  go build -o "${DNSTT_CLIENT_BIN}" ./dnstt-client
  popd >/dev/null
fi

mkdir -p "${KEY_DIR}"
if [[ ! -f "${KEY_DIR}/server.key" || ! -f "${KEY_DIR}/server.pub" ]]; then
  "${DNSTT_SERVER_BIN}" -gen-key -privkey-file "${KEY_DIR}/server.key" -pubkey-file "${KEY_DIR}/server.pub"
fi

run_case() {
  local case_name="$1"
  local target_mode="$2"
  local client_mode="$3"
  local run_id="${4:-}"
  local case_base="${case_name##*/}"
  local case_dir="${RUN_DIR}/${case_name}"
  local preface_args=()
  local target_preface_args=()
  local linger_args=()
  local target_linger_args=()
  local resolver_port="${DNS_LISTEN_PORT}"
  mkdir -p "${case_dir}"

  if [[ "${client_mode}" == "recv" ]]; then
    preface_args=(--preface-bytes 1)
    target_preface_args=(--preface-bytes 1)
  fi
  if [[ "${client_mode}" == "send" && "${TCP_LINGER_SECS}" != "0" ]]; then
    linger_args=(--linger-secs "${TCP_LINGER_SECS}")
  fi
  if [[ "${target_mode}" == "source" && "${TCP_LINGER_SECS}" != "0" ]]; then
    target_linger_args=(--linger-secs "${TCP_LINGER_SECS}")
  fi

  if [[ -n "${PROXY_DELAY_MS}" ]]; then
    local proxy_port="${PROXY_PORT:-$((DNS_LISTEN_PORT + 1))}"
    if [[ "${proxy_port}" -eq "${DNS_LISTEN_PORT}" ]]; then
      echo "Proxy port ${proxy_port} conflicts with DNS_LISTEN_PORT." >&2
      return 1
    fi
    local proxy_args=(
      --listen "127.0.0.1:${proxy_port}"
      --upstream "127.0.0.1:${DNS_LISTEN_PORT}"
      --delay-ms "${PROXY_DELAY_MS}"
      --dist "${PROXY_DIST}"
      --log "${case_dir}/dns_proxy.jsonl"
    )
    if [[ -n "${PROXY_JITTER_MS}" ]]; then
      proxy_args+=(--jitter-ms "${PROXY_JITTER_MS}")
    fi
    python3 "${ROOT_DIR}/scripts/interop/udp_capture_proxy.py" \
      "${proxy_args[@]}" \
      >"${case_dir}/dns_proxy.log" 2>&1 &
    PROXY_PID=$!
    resolver_port="${proxy_port}"
  fi

  python3 "${ROOT_DIR}/scripts/bench/tcp_bench.py" server \
    --listen "127.0.0.1:${TCP_TARGET_PORT}" \
    --mode "${target_mode}" \
    --bytes "${TRANSFER_BYTES}" \
    --chunk-size "${CHUNK_SIZE}" \
    --timeout "${SOCKET_TIMEOUT}" \
    "${target_preface_args[@]}" \
    "${target_linger_args[@]}" \
    --log "${case_dir}/target.jsonl" \
    >"${case_dir}/target.log" 2>&1 &
  TARGET_PID=$!

  "${DNSTT_SERVER_BIN}" \
    -udp "127.0.0.1:${DNS_LISTEN_PORT}" \
    -privkey-file "${KEY_DIR}/server.key" \
    "${DOMAIN}" \
    "127.0.0.1:${TCP_TARGET_PORT}" \
    >"${case_dir}/server.log" 2>&1 &
  SERVER_PID=$!

  "${DNSTT_CLIENT_BIN}" \
    -udp "127.0.0.1:${resolver_port}" \
    -pubkey-file "${KEY_DIR}/server.pub" \
    "${DOMAIN}" \
    "127.0.0.1:${CLIENT_TCP_PORT}" \
    >"${case_dir}/client.log" 2>&1 &
  CLIENT_PID=$!

  if [[ -n "${run_id}" ]]; then
    echo "Running ${case_name} benchmark (run ${run_id})..."
  else
    echo "Running ${case_name} benchmark..."
  fi
  sleep 2

  python3 "${ROOT_DIR}/scripts/bench/tcp_bench.py" client \
    --connect "127.0.0.1:${CLIENT_TCP_PORT}" \
    --mode "${client_mode}" \
    --bytes "${TRANSFER_BYTES}" \
    --chunk-size "${CHUNK_SIZE}" \
    --timeout "${SOCKET_TIMEOUT}" \
    "${preface_args[@]}" \
    "${linger_args[@]}" \
    --log "${case_dir}/bench.jsonl" \
    | tee "${case_dir}/bench.log"

  wait "${TARGET_PID}" || {
    echo "Target ${case_name} server failed." >&2
    return 1
  }
  local label="end-to-end ${case_base}"
  if [[ -n "${run_id}" ]]; then
    label="${label} (run ${run_id})"
  fi
  if [[ "${case_base}" == "exfil" ]]; then
    e2e_report "${label}" "${case_dir}/bench.jsonl" "${case_dir}/target.jsonl" "${TRANSFER_BYTES}"
  else
    e2e_report "${label}" "${case_dir}/target.jsonl" "${case_dir}/bench.jsonl" "${TRANSFER_BYTES}"
  fi
  cleanup_pids
}

if [[ -z "${PROXY_DELAY_MS}" ]]; then
  setup_netem
fi

if [[ "${RUNS}" -le 1 ]]; then
  if [[ "${RUN_EXFIL}" -ne 0 ]]; then
    run_case "exfil" "sink" "send"
  fi
  if [[ "${RUN_DOWNLOAD}" -ne 0 ]]; then
    run_case "download" "source" "recv"
  fi
else
  for run_id in $(seq 1 "${RUNS}"); do
    if [[ "${RUN_EXFIL}" -ne 0 ]]; then
      run_case "run-${run_id}/exfil" "sink" "send" "${run_id}"
    fi
    if [[ "${RUN_DOWNLOAD}" -ne 0 ]]; then
      run_case "run-${run_id}/download" "source" "recv" "${run_id}"
    fi
  done
fi

echo "Benchmarks OK; logs in ${RUN_DIR}."
