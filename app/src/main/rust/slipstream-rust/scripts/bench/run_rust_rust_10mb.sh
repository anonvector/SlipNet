#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CERT_DIR="${CERT_DIR:-"${ROOT_DIR}/fixtures/certs"}"

DNS_LISTEN_PORT="${DNS_LISTEN_PORT:-8853}"
PROXY_RECURSIVE_PORT="${PROXY_RECURSIVE_PORT:-5300}"
PROXY_AUTHORITATIVE_PORT="${PROXY_AUTHORITATIVE_PORT:-5301}"
USE_PROXY="${USE_PROXY:-0}"
RECURSIVE_ADDR="${RECURSIVE_ADDR:-}"
AUTHORITATIVE_ADDR="${AUTHORITATIVE_ADDR:-}"
TCP_TARGET_PORT="${TCP_TARGET_PORT:-5201}"
CLIENT_TCP_PORT="${CLIENT_TCP_PORT:-7000}"
DOMAIN="${DOMAIN:-test.com}"
SOCKET_TIMEOUT="${SOCKET_TIMEOUT:-}"
TRANSFER_BYTES="${TRANSFER_BYTES:-10485760}"
CHUNK_SIZE="${CHUNK_SIZE:-16384}"
PREFACE_BYTES="${PREFACE_BYTES:-1}"
RUNS="${RUNS:-1}"
RUN_EXFIL="${RUN_EXFIL:-1}"
RUN_DOWNLOAD="${RUN_DOWNLOAD:-1}"
MIN_AVG_MIB_S="${MIN_AVG_MIB_S:-}"
MIN_AVG_MIB_S_EXFIL="${MIN_AVG_MIB_S_EXFIL:-}"
MIN_AVG_MIB_S_DOWNLOAD="${MIN_AVG_MIB_S_DOWNLOAD:-}"
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
PROXY_REORDER_PROB="${PROXY_REORDER_PROB:-}"
PROXY_BURST_CORRELATION="${PROXY_BURST_CORRELATION:-}"
DEBUG_WAIT_SECS="${DEBUG_WAIT_SECS:-2}"
DEBUG_LOG_WAIT_SECS="${DEBUG_LOG_WAIT_SECS:-5}"
CLIENT_ARGS="${CLIENT_ARGS:-}"
RESOLVER_MODE="${RESOLVER_MODE:-resolver}"

client_extra_args=()
if [[ -n "${CLIENT_ARGS}" ]]; then
  read -r -a client_extra_args <<< "${CLIENT_ARGS}"
fi

case "${RESOLVER_MODE}" in
  resolver|authoritative|mixed) ;;
  *)
    echo "RESOLVER_MODE must be resolver, authoritative, or mixed (got: ${RESOLVER_MODE})" >&2
    exit 1
    ;;
esac

run_dir_prefix="bench-rust-rust"
default_timeout=30
default_download=10
if [[ "${RESOLVER_MODE}" == "mixed" ]]; then
  run_dir_prefix="bench-rust-rust-mixed"
fi
default_exfil=5

if [[ -z "${MIN_AVG_MIB_S_EXFIL}" ]]; then
  MIN_AVG_MIB_S_EXFIL="${default_exfil}"
fi
if [[ -z "${MIN_AVG_MIB_S_DOWNLOAD}" ]]; then
  MIN_AVG_MIB_S_DOWNLOAD="${default_download}"
fi
if [[ -n "${MIN_AVG_MIB_S}" ]]; then
  MIN_AVG_MIB_S_EXFIL="${MIN_AVG_MIB_S}"
  MIN_AVG_MIB_S_DOWNLOAD="${MIN_AVG_MIB_S}"
fi
if [[ -z "${SOCKET_TIMEOUT}" ]]; then
  SOCKET_TIMEOUT="${default_timeout}"
fi

RUN_DIR="${RUN_DIR:-"${ROOT_DIR}/.interop/${run_dir_prefix}-$(date +%Y%m%d_%H%M%S)"}"

if [[ ! -f "${CERT_DIR}/cert.pem" || ! -f "${CERT_DIR}/key.pem" ]]; then
  echo "Missing test certs in ${CERT_DIR}. Set CERT_DIR to override." >&2
  exit 1
fi

mkdir -p "${RUN_DIR}" "${ROOT_DIR}/.interop"

cleanup_pids() {
  for pid in "${CLIENT_PID:-}" "${SERVER_PID:-}" "${TARGET_PID:-}" "${PROXY_PID:-}" \
    "${PROXY_RECURSIVE_PID:-}" "${PROXY_AUTHORITATIVE_PID:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  CLIENT_PID=""
  SERVER_PID=""
  TARGET_PID=""
  PROXY_PID=""
  PROXY_RECURSIVE_PID=""
  PROXY_AUTHORITATIVE_PID=""
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

enforce_min_avg() {
  python3 - "$RUN_DIR" "$TRANSFER_BYTES" "$MIN_AVG_MIB_S" "$MIN_AVG_MIB_S_EXFIL" "$MIN_AVG_MIB_S_DOWNLOAD" "$RUN_EXFIL" "$RUN_DOWNLOAD" <<'PY'
import json
import pathlib
import sys

run_dir = pathlib.Path(sys.argv[1])
bytes_val = int(sys.argv[2])
min_avg = sys.argv[3]
min_exfil = float(sys.argv[4])
min_download = float(sys.argv[5])
run_exfil = int(sys.argv[6]) != 0
run_download = int(sys.argv[7]) != 0

def load_done(path: pathlib.Path):
    try:
        data = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in data:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event") == "done":
            return event
    return None

def e2e_mib_s(start_log: pathlib.Path, end_log: pathlib.Path):
    start = load_done(start_log)
    end = load_done(end_log)
    if not start or not end:
        return None
    start_ts = start.get("first_payload_ts")
    end_ts = end.get("last_payload_ts")
    if start_ts is None or end_ts is None:
        return None
    elapsed = end_ts - start_ts
    if elapsed <= 0:
        return None
    mib = bytes_val / (1024 * 1024)
    return mib / elapsed

def collect(case: str):
    values = []
    for path in run_dir.glob(f"**/{case}"):
        if not path.is_dir():
            continue
        if case == "exfil":
            start_log = path / "bench.jsonl"
            end_log = path / "target.jsonl"
        else:
            start_log = path / "target.jsonl"
            end_log = path / "bench.jsonl"
        if start_log.exists() and end_log.exists():
            rate = e2e_mib_s(start_log, end_log)
            if rate is not None:
                values.append(rate)
    return values

failed = False
if run_exfil:
    threshold = min_exfil
    if min_avg:
        threshold = float(min_avg)
    exfil_rates = collect("exfil")
    if not exfil_rates:
        print("exfil avg: missing timing data")
        failed = True
    else:
        exfil_avg = sum(exfil_rates) / len(exfil_rates)
        print(f"exfil avg MiB/s: {exfil_avg:.2f} (min {threshold:.2f})")
        if exfil_avg < threshold:
            failed = True

if run_download:
    threshold = min_download
    if min_avg:
        threshold = float(min_avg)
    download_rates = collect("download")
    if not download_rates:
        print("download avg: missing timing data")
        failed = True
    else:
        download_avg = sum(download_rates) / len(download_rates)
        print(f"download avg MiB/s: {download_avg:.2f} (min {threshold:.2f})")
        if download_avg < threshold:
            failed = True

raise SystemExit(1 if failed else 0)
PY
}

wait_for_log() {
  local label="$1"
  local log_path="$2"
  local pattern="$3"
  local attempts="${4:-10}"
  for _ in $(seq 1 "${attempts}"); do
    if [[ -s "${log_path}" ]] && grep -Eq "${pattern}" "${log_path}"; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for ${label}; see ${log_path}." >&2
  return 1
}

client_has_arg() {
  local needle="$1"
  shift
  for arg in "$@"; do
    if [[ "${arg}" == "${needle}" ]]; then
      return 0
    fi
  done
  return 1
}

client_debug_poll_enabled() {
  if client_has_arg "--debug-poll" "$@"; then
    return 0
  fi
  if client_has_arg "--debug-poll" "${client_extra_args[@]}"; then
    return 0
  fi
  return 1
}

wait_for_log_patterns() {
  local label="$1"
  local log_path="$2"
  local attempts="$3"
  shift 3
  local missing=()
  for _ in $(seq 1 "${attempts}"); do
    missing=()
    for pattern in "$@"; do
      if [[ ! -s "${log_path}" ]] || ! grep -Eq "${pattern}" "${log_path}"; then
        missing+=("${pattern}")
      fi
    done
    if [[ ${#missing[@]} -eq 0 ]]; then
      return 0
    fi
    sleep 1
  done
  echo "Timed out waiting for ${label} (${log_path}); missing patterns: ${missing[*]}." >&2
  return 1
}

start_client() {
  local log_path="$1"
  shift
  local rust_log=""
  if client_debug_poll_enabled "$@"; then
    rust_log="debug"
  fi
  if [[ -n "${rust_log}" ]]; then
    RUST_LOG="${rust_log}" "${ROOT_DIR}/target/release/slipstream-client" \
      --tcp-listen-port "${CLIENT_TCP_PORT}" \
      --domain "${DOMAIN}" \
      "$@" \
      "${client_extra_args[@]}" \
      >"${log_path}" 2>&1 &
  else
    "${ROOT_DIR}/target/release/slipstream-client" \
      --tcp-listen-port "${CLIENT_TCP_PORT}" \
      --domain "${DOMAIN}" \
      "$@" \
      "${client_extra_args[@]}" \
      >"${log_path}" 2>&1 &
  fi
  CLIENT_PID=$!
}

stop_client() {
  if [[ -n "${CLIENT_PID:-}" ]] && kill -0 "${CLIENT_PID}" 2>/dev/null; then
    kill "${CLIENT_PID}" 2>/dev/null || true
    wait "${CLIENT_PID}" 2>/dev/null || true
  fi
  CLIENT_PID=""
}

start_target() {
  local label="$1"
  local target_mode="$2"
  local preface_bytes="$3"
  local target_json="${RUN_DIR}/target_${label}.jsonl"
  local target_log="${RUN_DIR}/target_${label}.log"
  local target_args=(
    --listen "127.0.0.1:${TCP_TARGET_PORT}"
    --mode "${target_mode}"
    --bytes "${TRANSFER_BYTES}"
    --chunk-size "${CHUNK_SIZE}"
    --timeout "${SOCKET_TIMEOUT}"
    --log "${target_json}"
  )
  if [[ "${preface_bytes}" -gt 0 ]]; then
    target_args+=(--preface-bytes "${preface_bytes}")
  fi
  python3 "${ROOT_DIR}/scripts/bench/tcp_bench.py" server \
    "${target_args[@]}" \
    >"${target_log}" 2>&1 &
  TARGET_PID=$!
  if ! wait_for_log "bench target (${label})" "${target_json}" '"event": "listening"'; then
    return 1
  fi
}

stop_target() {
  if [[ -n "${TARGET_PID:-}" ]] && kill -0 "${TARGET_PID}" 2>/dev/null; then
    kill "${TARGET_PID}" 2>/dev/null || true
    wait "${TARGET_PID}" 2>/dev/null || true
  fi
  TARGET_PID=""
}

run_bench_client() {
  local label="$1"
  local client_mode="$2"
  local preface_bytes="$3"
  local bench_json="${RUN_DIR}/bench_${label}.jsonl"
  local bench_log="${RUN_DIR}/bench_${label}.log"
  local bench_args=(
    --connect "127.0.0.1:${CLIENT_TCP_PORT}"
    --mode "${client_mode}"
    --bytes "${TRANSFER_BYTES}"
    --chunk-size "${CHUNK_SIZE}"
    --timeout "${SOCKET_TIMEOUT}"
    --log "${bench_json}"
  )
  if [[ "${preface_bytes}" -gt 0 ]]; then
    bench_args+=(--preface-bytes "${preface_bytes}")
  fi
  if ! python3 "${ROOT_DIR}/scripts/bench/tcp_bench.py" client \
    "${bench_args[@]}" \
    >"${bench_log}" 2>&1; then
    echo "Bench transfer failed (${label}); see logs in ${RUN_DIR}." >&2
    return 1
  fi
}

extract_e2e_mib_s() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sys

start_path, end_path, bytes_s = sys.argv[1:4]

def load_done(path: str):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event") == "done":
                    return event
    except OSError as exc:
        print(f"Failed to read {path}: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Missing done event in {path}", file=sys.stderr)
    raise SystemExit(1)

start = load_done(start_path)
end = load_done(end_path)
start_ts = start.get("first_payload_ts")
end_ts = end.get("last_payload_ts")
if start_ts is None or end_ts is None:
    print("Missing payload timestamps", file=sys.stderr)
    raise SystemExit(1)
elapsed = end_ts - start_ts
if elapsed <= 0:
    print(f"Invalid timing window secs={elapsed:.6f}", file=sys.stderr)
    raise SystemExit(1)

bytes_val = int(bytes_s)
mib_s = (bytes_val / (1024 * 1024)) / elapsed
print(f"{mib_s:.2f}")
PY
}

report_throughput() {
  local label="$1"
  local mixed="$2"
  if [[ -n "${mixed}" ]]; then
    printf "throughput %s mixed MiB/s=%s\n" "${label}" "${mixed}"
  fi
}

enforce_min_throughput() {
  local label="$1"
  local value="$2"
  local threshold="$3"
  if [[ -z "${threshold}" ]]; then
    return 0
  fi
  python3 - "$label" "$value" "$threshold" <<'PY'
import sys

label, value_s, threshold_s = sys.argv[1:4]
try:
    value = float(value_s)
    threshold = float(threshold_s)
except ValueError:
    print(f"Invalid threshold compare for {label}: {value_s} vs {threshold_s}", file=sys.stderr)
    raise SystemExit(1)

if value < threshold:
    print(f"{label} mixed throughput {value:.2f} < minimum {threshold:.2f}", file=sys.stderr)
    raise SystemExit(1)
print(f"{label} mixed throughput minimum ok ({value:.2f} >= {threshold:.2f})")
PY
}

run_client_bench() {
  local label="$1"
  local target_mode="$2"
  local client_mode="$3"
  shift 3
  local client_log="${RUN_DIR}/client_${label}.log"
  local target_json="${RUN_DIR}/target_${label}.jsonl"
  local bench_json="${RUN_DIR}/bench_${label}.jsonl"
  local preface_bytes=0
  local start_path="${bench_json}"
  local end_path="${target_json}"
  local debug_poll=0

  if [[ "${client_mode}" == "recv" ]]; then
    preface_bytes="${PREFACE_BYTES}"
    start_path="${target_json}"
    end_path="${bench_json}"
  fi
  if client_debug_poll_enabled "$@"; then
    debug_poll=1
  fi

  if ! start_target "${label}" "${target_mode}" "${preface_bytes}"; then
    stop_target
    return 1
  fi
  start_client "${client_log}" "$@"
  echo "Waiting for Rust client (${label}) to accept connections..." >&2
  if ! wait_for_log "Rust client (${label})" "${client_log}" "Listening on TCP port"; then
    stop_client
    stop_target
    return 1
  fi
  if ! run_bench_client "${label}" "${client_mode}" "${preface_bytes}"; then
    stop_client
    stop_target
    return 1
  fi
  if ! wait "${TARGET_PID}"; then
    echo "Target server failed (${label}); see logs in ${RUN_DIR}." >&2
    stop_client
    stop_target
    return 1
  fi
  if [[ "${label}" == mixed_* && "${debug_poll}" == "1" ]]; then
    if ! wait_for_log_patterns \
      "mixed debug output (${label})" \
      "${client_log}" \
      "${DEBUG_LOG_WAIT_SECS}" \
      "mode=Recursive" \
      "mode=Authoritative" \
      "mode=Authoritative.*pacing_rate="; then
      stop_client
      stop_target
      return 1
    fi
    sleep "${DEBUG_WAIT_SECS}"
  fi
  stop_client
  stop_target

  extract_e2e_mib_s "${start_path}" "${end_path}" "${TRANSFER_BYTES}"
}

cargo build -p slipstream-server -p slipstream-client --release

run_case() {
  local case_name="$1"
  local target_mode="$2"
  local client_mode="$3"
  local run_id="${4:-}"
  local case_base="${case_name##*/}"
  local case_dir="${RUN_DIR}/${case_name}"
  local preface_args=()
  local target_preface_args=()
  local resolver_port="${DNS_LISTEN_PORT}"
  mkdir -p "${case_dir}"

  if [[ "${client_mode}" == "recv" && "${PREFACE_BYTES}" -gt 0 ]]; then
    preface_args=(--preface-bytes "${PREFACE_BYTES}")
    target_preface_args=(--preface-bytes "${PREFACE_BYTES}")
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
    if [[ -n "${PROXY_BURST_CORRELATION}" ]]; then
      proxy_args+=(--burst-correlation "${PROXY_BURST_CORRELATION}")
    fi
    if [[ -n "${PROXY_REORDER_PROB}" ]]; then
      proxy_args+=(--reorder-rate "${PROXY_REORDER_PROB}")
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
    --log "${case_dir}/target.jsonl" \
    >"${case_dir}/target.log" 2>&1 &
  TARGET_PID=$!

  "${ROOT_DIR}/target/release/slipstream-server" \
    --dns-listen-port "${DNS_LISTEN_PORT}" \
    --target-address "127.0.0.1:${TCP_TARGET_PORT}" \
    --domain "${DOMAIN}" \
    --cert "${CERT_DIR}/cert.pem" \
    --key "${CERT_DIR}/key.pem" \
    >"${case_dir}/server.log" 2>&1 &
  SERVER_PID=$!

  "${ROOT_DIR}/target/release/slipstream-client" \
    --tcp-listen-port "${CLIENT_TCP_PORT}" \
    --"${RESOLVER_MODE}" "127.0.0.1:${resolver_port}" \
    --domain "${DOMAIN}" \
    "${client_extra_args[@]}" \
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

run_mixed() {
  local use_proxy="${USE_PROXY}"
  if [[ -n "${PROXY_DELAY_MS}" ]]; then
    use_proxy=1
  fi

  if [[ "${use_proxy}" == "1" ]]; then
    RECURSIVE_ADDR="${RECURSIVE_ADDR:-127.0.0.1:${PROXY_RECURSIVE_PORT}}"
    AUTHORITATIVE_ADDR="${AUTHORITATIVE_ADDR:-127.0.0.1:${PROXY_AUTHORITATIVE_PORT}}"
  else
    RECURSIVE_ADDR="${RECURSIVE_ADDR:-127.0.0.1:${DNS_LISTEN_PORT}}"
    AUTHORITATIVE_ADDR="${AUTHORITATIVE_ADDR:-[::1]:${DNS_LISTEN_PORT}}"
  fi

  if [[ "${RECURSIVE_ADDR}" == "${AUTHORITATIVE_ADDR}" ]]; then
    echo "Recursive and authoritative resolver addresses must differ; set RECURSIVE_ADDR/AUTHORITATIVE_ADDR or USE_PROXY=1." >&2
    return 1
  fi

  if [[ -z "${PROXY_DELAY_MS}" ]]; then
    setup_netem
  fi

  "${ROOT_DIR}/target/release/slipstream-server" \
    --dns-listen-port "${DNS_LISTEN_PORT}" \
    --target-address "127.0.0.1:${TCP_TARGET_PORT}" \
    --domain "${DOMAIN}" \
    --cert "${CERT_DIR}/cert.pem" \
    --key "${CERT_DIR}/key.pem" \
    >"${RUN_DIR}/server.log" 2>&1 &
  SERVER_PID=$!

  if [[ "${use_proxy}" == "1" ]]; then
    local proxy_recursive_args=(
      --listen "127.0.0.1:${PROXY_RECURSIVE_PORT}"
      --upstream "127.0.0.1:${DNS_LISTEN_PORT}"
      --log "${RUN_DIR}/dns_recursive.jsonl"
    )
    local proxy_authoritative_args=(
      --listen "127.0.0.1:${PROXY_AUTHORITATIVE_PORT}"
      --upstream "127.0.0.1:${DNS_LISTEN_PORT}"
      --log "${RUN_DIR}/dns_authoritative.jsonl"
    )
    if [[ -n "${PROXY_DELAY_MS}" ]]; then
      proxy_recursive_args+=(--delay-ms "${PROXY_DELAY_MS}" --dist "${PROXY_DIST}")
      proxy_authoritative_args+=(--delay-ms "${PROXY_DELAY_MS}" --dist "${PROXY_DIST}")
      if [[ -n "${PROXY_JITTER_MS}" ]]; then
        proxy_recursive_args+=(--jitter-ms "${PROXY_JITTER_MS}")
        proxy_authoritative_args+=(--jitter-ms "${PROXY_JITTER_MS}")
      fi
      if [[ -n "${PROXY_BURST_CORRELATION}" ]]; then
        proxy_recursive_args+=(--burst-correlation "${PROXY_BURST_CORRELATION}")
        proxy_authoritative_args+=(--burst-correlation "${PROXY_BURST_CORRELATION}")
      fi
      if [[ -n "${PROXY_REORDER_PROB}" ]]; then
        proxy_recursive_args+=(--reorder-rate "${PROXY_REORDER_PROB}")
        proxy_authoritative_args+=(--reorder-rate "${PROXY_REORDER_PROB}")
      fi
    fi
    python3 "${ROOT_DIR}/scripts/interop/udp_capture_proxy.py" \
      "${proxy_recursive_args[@]}" \
      >"${RUN_DIR}/udp_proxy_recursive.log" 2>&1 &
    PROXY_RECURSIVE_PID=$!

    python3 "${ROOT_DIR}/scripts/interop/udp_capture_proxy.py" \
      "${proxy_authoritative_args[@]}" \
      >"${RUN_DIR}/udp_proxy_authoritative.log" 2>&1 &
    PROXY_AUTHORITATIVE_PID=$!
  fi

  local mixed_download_mib_s=""
  local mixed_exfil_mib_s=""

  if [[ "${RUN_DOWNLOAD}" != "0" ]]; then
    if ! mixed_download_mib_s=$(run_client_bench \
      mixed_download \
      source \
      recv \
      --authoritative "${AUTHORITATIVE_ADDR}" \
      --resolver "${RECURSIVE_ADDR}"); then
      return 1
    fi
    if ! enforce_min_throughput "download" "${mixed_download_mib_s}" "${MIN_AVG_MIB_S_DOWNLOAD}"; then
      return 1
    fi
  fi

  if [[ "${RUN_EXFIL}" != "0" ]]; then
    if ! mixed_exfil_mib_s=$(run_client_bench \
      mixed_exfil \
      sink \
      send \
      --authoritative "${AUTHORITATIVE_ADDR}" \
      --resolver "${RECURSIVE_ADDR}"); then
      return 1
    fi
    if ! enforce_min_throughput "exfil" "${mixed_exfil_mib_s}" "${MIN_AVG_MIB_S_EXFIL}"; then
      return 1
    fi
  fi

  if [[ "${RUN_DOWNLOAD}" == "0" && "${RUN_EXFIL}" == "0" ]]; then
    echo "RUN_DOWNLOAD and RUN_EXFIL are both disabled; nothing to run." >&2
    return 1
  fi

  if [[ "${use_proxy}" == "1" ]]; then
    python3 - "${RUN_DIR}/dns_recursive.jsonl" "${RUN_DIR}/dns_authoritative.jsonl" <<'PY'
import json
import sys

paths = [("recursive", sys.argv[1]), ("authoritative", sys.argv[2])]
failed = False

for label, path in paths:
    counts = {"client_to_server": 0, "server_to_client": 0}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                direction = entry.get("direction")
                if direction in counts:
                    counts[direction] += 1
    except OSError as exc:
        print(f"{label} capture missing ({path}): {exc}", file=sys.stderr)
        failed = True
        continue

    missing = [direction for direction, total in counts.items() if total == 0]
    if missing:
        print(f"{label} capture missing directions: {missing} ({counts})", file=sys.stderr)
        failed = True
    else:
        print(
            f"{label} capture: client_to_server={counts['client_to_server']} "
            f"server_to_client={counts['server_to_client']}"
        )

if failed:
    raise SystemExit(1)
PY
  fi

  if [[ "${RUN_DOWNLOAD}" != "0" ]]; then
    report_throughput "download" "${mixed_download_mib_s}"
  fi
  if [[ "${RUN_EXFIL}" != "0" ]]; then
    report_throughput "exfil" "${mixed_exfil_mib_s}"
  fi

  echo "Interop mixed OK; logs in ${RUN_DIR}."
}

if [[ "${RESOLVER_MODE}" == "mixed" ]]; then
  run_mixed
  exit $?
fi

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

enforce_min_avg
echo "Benchmarks OK; logs in ${RUN_DIR}."
