#!/usr/bin/env bash
set -euo pipefail
# Dev-only: internal profiling helper; not part of the public toolchain.

usage() {
  cat <<'EOF'
Usage: scripts/dev/repro_high_cpu.sh [options]

Reproduce post-load CPU behavior for slipstream-server.

Options:
  --release                 Use release binaries (target/release).
  --build                   Build slipstream-client/server if binaries are missing.
  --server-bin PATH         Path to slipstream-server binary.
  --client-bin PATH         Path to slipstream-client binary.
  --domain DOMAIN           Domain to use (default: example.com).
  --dns-port PORT           DNS listen port for server (default: 8853).
  --tcp-port PORT           TCP listen port for client (default: 5201).
  --target-host HOST        Target TCP host (default: 127.0.0.1).
  --target-port PORT        Target TCP port (default: 32377).
  --streams N               Number of parallel TCP streams (default: 8).
  --mb N                    MiB per stream (default: 20).
  --bytes N                 Bytes per stream (overrides --mb).
  --load-seconds N          Max seconds to run each load stream (default: 0 = no limit).
  --interval SEC            CPU sampling interval seconds (default: 2).
  --samples N               Number of CPU samples (default: 15).
  --sample-queue            Log UDP recv/send queue for the DNS port during sampling.
  --congestion ALG          Congestion control (default: bbr).
  --strace-seconds N        Run strace -c on the server for N seconds after load.
  --perf-seconds N          Run perf record -g on the server for N seconds after load.
  --perf-freq N             perf record frequency (default: 99).
  --nc-quit SECONDS         Seconds to wait after EOF before netcat closes (default: 1).
  --cert PATH               TLS cert for server (default: fixtures/certs/cert.pem).
  --key PATH                TLS key for server (default: fixtures/certs/key.pem).
  --debug-streams           Enable --debug-streams in server/client.
  --debug-commands          Enable --debug-commands in server.
  --cleanup                 Remove temp logs on exit.
  -h, --help                Show this help text.
EOF
}

domain="example.com"
dns_port=8853
tcp_port=5201
target_host="127.0.0.1"
target_port=32377
streams=8
mb_per_stream=20
bytes_per_stream=""
load_seconds=0
interval=2
samples=15
sample_queue=0
congestion="bbr"
strace_seconds=0
perf_seconds=0
perf_freq=99
nc_quit=1
cert="fixtures/certs/cert.pem"
key="fixtures/certs/key.pem"
release=0
build=0
keep_logs=1
debug_streams=0
debug_commands=0
server_bin=""
client_bin=""
server_bin_set=0
client_bin_set=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release)
      release=1
      ;;
    --build)
      build=1
      ;;
    --server-bin)
      server_bin="${2:-}"
      server_bin_set=1
      shift
      ;;
    --client-bin)
      client_bin="${2:-}"
      client_bin_set=1
      shift
      ;;
    --domain)
      domain="${2:-}"
      shift
      ;;
    --dns-port)
      dns_port="${2:-}"
      shift
      ;;
    --tcp-port)
      tcp_port="${2:-}"
      shift
      ;;
    --target-host)
      target_host="${2:-}"
      shift
      ;;
    --target-port)
      target_port="${2:-}"
      shift
      ;;
    --streams)
      streams="${2:-}"
      shift
      ;;
    --mb)
      mb_per_stream="${2:-}"
      shift
      ;;
    --bytes)
      bytes_per_stream="${2:-}"
      shift
      ;;
    --load-seconds)
      load_seconds="${2:-}"
      shift
      ;;
    --interval)
      interval="${2:-}"
      shift
      ;;
    --samples)
      samples="${2:-}"
      shift
      ;;
    --sample-queue)
      sample_queue=1
      ;;
    --congestion)
      congestion="${2:-}"
      shift
      ;;
    --strace-seconds)
      strace_seconds="${2:-}"
      shift
      ;;
    --perf-seconds)
      perf_seconds="${2:-}"
      shift
      ;;
    --perf-freq)
      perf_freq="${2:-}"
      shift
      ;;
    --nc-quit)
      nc_quit="${2:-}"
      shift
      ;;
    --cert)
      cert="${2:-}"
      shift
      ;;
    --key)
      key="${2:-}"
      shift
      ;;
    --debug-streams)
      debug_streams=1
      ;;
    --debug-commands)
      debug_commands=1
      ;;
    --cleanup)
      keep_logs=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ "$release" -eq 1 ]]; then
  if [[ "$server_bin_set" -eq 0 ]]; then
    server_bin="target/release/slipstream-server"
  fi
  if [[ "$client_bin_set" -eq 0 ]]; then
    client_bin="target/release/slipstream-client"
  fi
else
  if [[ "$server_bin_set" -eq 0 ]]; then
    server_bin="target/debug/slipstream-server"
  fi
  if [[ "$client_bin_set" -eq 0 ]]; then
    client_bin="target/debug/slipstream-client"
  fi
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to run the target TCP sink." >&2
  exit 1
fi

if ! command -v nc >/dev/null 2>&1; then
  echo "nc (netcat) is required to generate load." >&2
  exit 1
fi
if [[ "$load_seconds" -gt 0 ]] && ! command -v timeout >/dev/null 2>&1; then
  echo "timeout is required for --load-seconds." >&2
  exit 1
fi
if [[ "$strace_seconds" -gt 0 ]] && ! command -v strace >/dev/null 2>&1; then
  echo "strace is required for --strace-seconds." >&2
  exit 1
fi
if [[ "$perf_seconds" -gt 0 ]] && ! command -v perf >/dev/null 2>&1; then
  echo "perf is required for --perf-seconds." >&2
  exit 1
fi

if [[ ! -x "$server_bin" || ! -x "$client_bin" ]]; then
  if [[ "$build" -eq 1 ]]; then
    if ! command -v cargo >/dev/null 2>&1; then
      echo "cargo is required to build slipstream binaries." >&2
      exit 1
    fi
    if [[ "$release" -eq 1 ]]; then
      cargo build --release -p slipstream-server -p slipstream-client
    else
      cargo build -p slipstream-server -p slipstream-client
    fi
  else
    echo "Missing binaries: $server_bin or $client_bin" >&2
    echo "Run with --build or specify --server-bin/--client-bin." >&2
    exit 1
  fi
fi

tmpdir="$(mktemp -d -t slipstream-repro.XXXXXX)"

cleanup() {
  local rc=$?
  if [[ -n "${client_pid:-}" ]]; then
    kill "$client_pid" 2>/dev/null || true
  fi
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" 2>/dev/null || true
  fi
  if [[ -n "${target_pid:-}" ]]; then
    kill "$target_pid" 2>/dev/null || true
  fi
  if [[ "$keep_logs" -eq 0 ]]; then
    rm -rf "$tmpdir"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

echo "Logs: $tmpdir"

python3 -u - <<PY >"$tmpdir/target.log" 2>&1 &
import socket
import threading

host = "${target_host}"
port = int("${target_port}")
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen()
print(f"listening {host}:{port}", flush=True)

def handle(conn):
  try:
    while True:
      data = conn.recv(65536)
      if not data:
        break
  finally:
    conn.close()

while True:
  conn, _ = s.accept()
  t = threading.Thread(target=handle, args=(conn,), daemon=True)
  t.start()
PY
target_pid=$!

server_env=()
server_args=()
client_args=()
if [[ "$debug_streams" -eq 1 ]]; then
  server_args+=(--debug-streams)
  client_args+=(--debug-streams)
fi
if [[ "$debug_commands" -eq 1 ]]; then
  server_args+=(--debug-commands)
fi

env "${server_env[@]}" "$server_bin" \
  -l "$dns_port" \
  -a "${target_host}:${target_port}" \
  -d "$domain" \
  -c "$cert" \
  -k "$key" \
  "${server_args[@]}" \
  >"$tmpdir/server.log" 2>&1 &
server_pid=$!

"$client_bin" \
  -l "$tcp_port" \
  -r "127.0.0.1:${dns_port}" \
  -d "$domain" \
  -c "$congestion" \
  "${client_args[@]}" \
  >"$tmpdir/client.log" 2>&1 &
client_pid=$!

ready=0
for _ in $(seq 1 50); do
  if command -v rg >/dev/null 2>&1; then
    if rg -q "Connection ready" "$tmpdir/client.log"; then
      ready=1
      break
    fi
  else
    if grep -q "Connection ready" "$tmpdir/client.log"; then
      ready=1
      break
    fi
  fi
  if ! kill -0 "$client_pid" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if [[ "$ready" -ne 1 ]]; then
  echo "Client did not become ready." >&2
  tail -n 20 "$tmpdir/client.log" >&2 || true
  tail -n 20 "$tmpdir/server.log" >&2 || true
  exit 1
fi

load_label="${mb_per_stream} MiB"
if [[ -n "$bytes_per_stream" ]]; then
  load_label="${bytes_per_stream} bytes"
fi
echo "Generating load: ${streams} streams x ${load_label}"
load_pids=()
for _ in $(seq 1 "$streams"); do
  if [[ -n "$bytes_per_stream" ]]; then
    dd_args=(if=/dev/zero bs=1 count="$bytes_per_stream" status=none)
  else
    dd_args=(if=/dev/zero bs=1M count="$mb_per_stream" status=none)
  fi
  if [[ "$load_seconds" -gt 0 ]]; then
    (dd "${dd_args[@]}" | timeout "${load_seconds}s" nc "${nc_args[@]}" 127.0.0.1 "$tcp_port") || true &
  else
    (dd "${dd_args[@]}" | nc "${nc_args[@]}" 127.0.0.1 "$tcp_port") || true &
  fi
  load_pids+=("$!")
done
for pid in "${load_pids[@]}"; do
  wait "$pid" || true
done

kill -INT "$client_pid" 2>/dev/null || true

if [[ "$strace_seconds" -gt 0 ]]; then
  timeout "${strace_seconds}s" strace -c -p "$server_pid" -o "$tmpdir/strace.log" || true
fi
if [[ "$perf_seconds" -gt 0 ]]; then
  if perf record -g -F "$perf_freq" -p "$server_pid" -o "$tmpdir/perf.data" -- sleep "$perf_seconds"; then
    perf report --stdio -i "$tmpdir/perf.data" >"$tmpdir/perf.txt"
  else
    echo "perf record failed" >"$tmpdir/perf.txt"
  fi
fi

echo "Sampling CPU for $((interval * samples))s"
clk_tck=$(getconf CLK_TCK)
prev_total=""
for _ in $(seq 1 "$samples"); do
  ts=$(date +%s)
  if ps -p "$server_pid" >/dev/null 2>&1; then
    stat=$(<"/proc/$server_pid/stat")
    stat=${stat#*) }
    read -r utime stime < <(printf '%s\n' "$stat" | awk '{print $12, $13}')
    total=$((utime + stime))
    if [[ -n "$prev_total" ]]; then
      delta=$((total - prev_total))
      cpu=$(awk -v d="$delta" -v hz="$clk_tck" -v t="$interval" 'BEGIN { if (t > 0 && hz > 0) printf "%.1f", (d / hz) / t * 100; else print "0.0" }')
    else
      cpu="0.0"
    fi
    prev_total="$total"
    rss=$(ps -p "$server_pid" -o rss= | tr -d ' ')
    if [[ "$sample_queue" -eq 1 ]]; then
      queue=$(ss -u -n -l 2>/dev/null | awk -v port=":${dns_port}" '$4 ~ port {print $2, $3; found=1} END {if (!found) print "na na"}')
      recvq=$(printf '%s' "$queue" | awk '{print $1}')
      sendq=$(printf '%s' "$queue" | awk '{print $2}')
      echo "$ts cpu=${cpu} rss_kb=${rss} recvq=${recvq} sendq=${sendq}" >>"$tmpdir/cpu.log"
    else
      echo "$ts cpu=${cpu} rss_kb=${rss}" >>"$tmpdir/cpu.log"
    fi
  else
    echo "$ts server_exited" >>"$tmpdir/cpu.log"
    break
  fi
  sleep "$interval"
done

echo "--- client.log (tail) ---"
tail -n 5 "$tmpdir/client.log" || true
echo "--- server.log (tail) ---"
tail -n 5 "$tmpdir/server.log" || true
echo "--- cpu.log ---"
cat "$tmpdir/cpu.log" || true
nc_supports_q=0
if nc -h 2>&1 | grep -q " -q "; then
  nc_supports_q=1
fi
nc_args=(-N)
if [[ "$nc_supports_q" -eq 1 ]]; then
  nc_args+=(-q "$nc_quit")
fi
