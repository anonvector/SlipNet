#!/usr/bin/env python3
"""
DNS Multiplexer Proxy for DNSTT/NoizDNS

Distributes DNS queries across multiple upstream resolvers using round-robin
or random distribution. Designed as a middle proxy on a datacenter server to
bypass DPI restrictions on mobile ISP networks.

Supports two upstream modes:
  - UDP/TCP (plain DNS to resolvers like 8.8.8.8)
  - DoH (DNS over HTTPS to resolvers like https://dns.google/dns-query)

Usage:
    python3 dns-mux.py -r 8.8.8.8 -r 1.1.1.1 -r 9.9.9.9
    python3 dns-mux.py --doh -f resolvers-doh.txt --cover --stats
    python3 dns-mux.py --doh -r https://dns.google/dns-query -r https://cloudflare-dns.com/dns-query
"""

import argparse
import base64
import socket
import struct
import threading
import itertools
import random
import signal
import sys
import time
import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.request import Request, urlopen
from urllib.error import URLError

DNS_BUFFER_SIZE = 4096
UPSTREAM_TIMEOUT = 5.0
HEALTH_CHECK_INTERVAL = 30
STATS_INTERVAL = 60
MAX_WORKERS = 256

DOH_CONTENT_TYPE = "application/dns-message"

# Legitimate domains for cover traffic
COVER_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "cloudflare.com", "facebook.com", "github.com", "wikipedia.org",
    "yahoo.com", "bing.com", "reddit.com", "twitter.com",
    "linkedin.com", "netflix.com", "instagram.com", "whatsapp.com",
]

# Default DoH resolvers
DEFAULT_DOH_RESOLVERS = [
    "https://dns.google/dns-query",
    "https://cloudflare-dns.com/dns-query",
    "https://doh.opendns.com/dns-query",
    "https://doh.cleanbrowsing.org/doh/security-filter",
    "https://dns.nextdns.io/dns-query",
    "https://doh.mullvad.net/dns-query",
    "https://dns0.eu/dns-query",
    "https://ordns.he.net/dns-query",
    # May not work from all locations
    "https://dns.quad9.net/dns-query",
    "https://dns.adguard-dns.com/dns-query",
    "https://free.shecan.ir/dns-query",
    "https://dns.403.online/dns-query",
]


def build_dns_query(domain, qtype=1):
    """Build a minimal DNS A-record query packet."""
    txid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00"
    question += struct.pack("!HH", qtype, 1)
    return header + question


def _send_query_udp(data, resolver):
    """Send DNS query via UDP. resolver is (ip, port) tuple."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(UPSTREAM_TIMEOUT)
        sock.sendto(data, resolver)
        response, _ = sock.recvfrom(DNS_BUFFER_SIZE)
        return response
    finally:
        sock.close()


def _send_query_doh(data, resolver):
    """Send DNS query via DoH (HTTPS POST). resolver is a URL string."""
    req = Request(
        resolver,
        data=data,
        headers={
            "Content-Type": DOH_CONTENT_TYPE,
            "Accept": DOH_CONTENT_TYPE,
        },
        method="POST",
    )
    resp = urlopen(req, timeout=UPSTREAM_TIMEOUT)
    return resp.read()


class ResolverPool:
    """Pool of DNS resolvers with health tracking and round-robin/random distribution."""

    def __init__(self, resolvers, mode="round-robin", doh=False):
        self.resolvers = resolvers
        self.mode = mode
        self.doh = doh
        self._lock = threading.Lock()
        self._healthy = {r: True for r in resolvers}
        self._healthy_cache = list(resolvers)
        self._stats = defaultdict(lambda: {"sent": 0, "ok": 0, "fail": 0})
        self._fail_streak = defaultdict(int)
        self._rr_index = 0

    def _rebuild_healthy_cache(self):
        self._healthy_cache = [r for r in self.resolvers if self._healthy[r]]
        if not self._healthy_cache:
            self._healthy_cache = list(self.resolvers)

    def get_next(self):
        with self._lock:
            healthy = self._healthy_cache
            if self.mode == "random":
                return random.choice(healthy)
            idx = self._rr_index % len(healthy)
            self._rr_index += 1
            return healthy[idx]

    def send_query(self, data, resolver):
        """Send a query using the appropriate transport (UDP or DoH)."""
        if self.doh:
            return _send_query_doh(data, resolver)
        return _send_query_udp(data, resolver)

    def mark_success(self, resolver):
        with self._lock:
            was_unhealthy = not self._healthy[resolver]
            self._healthy[resolver] = True
            self._stats[resolver]["ok"] += 1
            self._fail_streak[resolver] = 0
            if was_unhealthy:
                self._rebuild_healthy_cache()

    def mark_failure(self, resolver):
        with self._lock:
            self._stats[resolver]["fail"] += 1
            self._fail_streak[resolver] += 1
            if self._fail_streak[resolver] >= 3 and self._healthy[resolver]:
                self._healthy[resolver] = False
                self._rebuild_healthy_cache()

    def mark_sent(self, resolver):
        with self._lock:
            self._stats[resolver]["sent"] += 1

    def health_check(self):
        query = build_dns_query("google.com")

        def probe(resolver):
            try:
                self.send_query(query, resolver)
                return resolver, True
            except Exception:
                return resolver, False

        with ThreadPoolExecutor(max_workers=min(len(self.resolvers), 20)) as pool:
            results = pool.map(probe, self.resolvers)

        with self._lock:
            for resolver, alive in results:
                self._healthy[resolver] = alive
                if alive:
                    self._fail_streak[resolver] = 0
            self._rebuild_healthy_cache()

    def get_stats_str(self):
        with self._lock:
            lines = []
            for r in self.resolvers:
                s = self._stats[r]
                status = "UP" if self._healthy[r] else "DOWN"
                label = r if isinstance(r, str) else f"{r[0]}:{r[1]}"
                lines.append(
                    f"  {label:>40} [{status:>4}] "
                    f"sent={s['sent']:<6} ok={s['ok']:<6} fail={s['fail']}"
                )
            return "\n".join(lines)

    def healthy_count(self):
        with self._lock:
            return sum(1 for v in self._healthy.values() if v)


def _bind_socket(sock_type, addr, port, listen_backlog=None):
    sock = socket.socket(socket.AF_INET, sock_type)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((addr, port))
    if listen_backlog is not None:
        sock.listen(listen_backlog)
    sock.settimeout(1.0)
    return sock


def _bind_with_retry(sock_type, addr, port, running_flag, listen_backlog=None):
    while running_flag():
        try:
            return _bind_socket(sock_type, addr, port, listen_backlog)
        except OSError as e:
            proto = "TCP" if sock_type == socket.SOCK_STREAM else "UDP"
            logging.warning(f"{proto} bind to {addr}:{port} failed ({e}), retrying in 3s...")
            time.sleep(3)
    return None


class UDPProxy:
    """UDP DNS proxy that multiplexes queries across resolver pool."""

    def __init__(self, listen_addr, listen_port, pool):
        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self.pool = pool
        self.sock = None
        self.running = False
        self.query_count = 0
        self._executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def start(self):
        self.running = True
        self.sock = _bind_with_retry(
            socket.SOCK_DGRAM, self.listen_addr, self.listen_port,
            lambda: self.running,
        )
        if not self.sock:
            return

        logging.info(f"UDP proxy listening on {self.listen_addr}:{self.listen_port}")

        while self.running:
            try:
                data, client_addr = self.sock.recvfrom(DNS_BUFFER_SIZE)
                self.query_count += 1
                self._executor.submit(self._forward, data, client_addr)
            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    logging.error("UDP socket error, rebinding in 3s...")
                    time.sleep(3)
                    try:
                        self.sock.close()
                    except Exception:
                        pass
                    self.sock = _bind_with_retry(
                        socket.SOCK_DGRAM, self.listen_addr, self.listen_port,
                        lambda: self.running,
                    )
                    if self.sock:
                        logging.info("UDP socket rebound successfully")
                    else:
                        break

    def _forward(self, data, client_addr):
        resolver = self.pool.get_next()
        self.pool.mark_sent(resolver)

        try:
            response = self.pool.send_query(data, resolver)
            self.sock.sendto(response, client_addr)
            self.pool.mark_success(resolver)
        except Exception as e:
            self.pool.mark_failure(resolver)
            logging.debug(f"Forward to {resolver} failed: {e}")

            retry = self.pool.get_next()
            if retry != resolver:
                try:
                    response = self.pool.send_query(data, retry)
                    self.sock.sendto(response, client_addr)
                    self.pool.mark_success(retry)
                except Exception:
                    self.pool.mark_failure(retry)

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
        self._executor.shutdown(wait=False)


class TCPProxy:
    """TCP DNS proxy with 2-byte length framing."""

    def __init__(self, listen_addr, listen_port, pool):
        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self.pool = pool
        self.sock = None
        self.running = False
        self._executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def start(self):
        self.running = True
        self.sock = _bind_with_retry(
            socket.SOCK_STREAM, self.listen_addr, self.listen_port,
            lambda: self.running, listen_backlog=128,
        )
        if not self.sock:
            return

        logging.info(f"TCP proxy listening on {self.listen_addr}:{self.listen_port}")

        while self.running:
            try:
                conn, addr = self.sock.accept()
                self._executor.submit(self._handle, conn, addr)
            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    logging.error("TCP socket error")
                break

    def _handle(self, conn, addr):
        resolver = None
        try:
            conn.settimeout(10.0)

            length_data = conn.recv(2)
            if len(length_data) < 2:
                return
            msg_len = struct.unpack("!H", length_data)[0]

            data = bytearray()
            while len(data) < msg_len:
                chunk = conn.recv(msg_len - len(data))
                if not chunk:
                    break
                data.extend(chunk)

            if len(data) != msg_len:
                return

            resolver = self.pool.get_next()
            self.pool.mark_sent(resolver)

            response = self.pool.send_query(bytes(data), resolver)
            self.pool.mark_success(resolver)
            conn.sendall(struct.pack("!H", len(response)) + response)
        except Exception as e:
            if resolver:
                self.pool.mark_failure(resolver)
            logging.debug(f"TCP handler error: {e}")
        finally:
            conn.close()

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()
        self._executor.shutdown(wait=False)


class CoverTraffic:
    """Generates periodic legitimate DNS queries to blend tunnel traffic."""

    def __init__(self, pool, interval_min=5.0, interval_max=15.0):
        self.pool = pool
        self.interval_min = interval_min
        self.interval_max = interval_max
        self.running = False

    def start(self):
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        logging.info(
            f"Cover traffic enabled (interval: {self.interval_min}-{self.interval_max}s)"
        )

    def _loop(self):
        while self.running:
            domain = random.choice(COVER_DOMAINS)
            resolver = self.pool.get_next()
            query = build_dns_query(domain)
            try:
                self.pool.send_query(query, resolver)
                logging.debug(f"Cover: {domain} via {resolver}")
            except Exception:
                pass
            time.sleep(random.uniform(self.interval_min, self.interval_max))

    def stop(self):
        self.running = False


class DNSMultiplexer:
    """Main DNS multiplexer combining UDP, TCP proxy and cover traffic."""

    def __init__(self, args):
        self.args = args
        self.doh_mode = args.doh
        resolvers = self._parse_resolvers()
        if not resolvers:
            if self.doh_mode:
                logging.info("No resolvers specified, using default DoH resolvers")
                resolvers = list(DEFAULT_DOH_RESOLVERS)
            else:
                logging.error("No resolvers configured. Use -r or -f to specify resolvers.")
                sys.exit(1)

        self.pool = ResolverPool(resolvers, mode=args.mode, doh=self.doh_mode)

        try:
            host, port_str = args.listen.rsplit(":", 1)
            port = int(port_str)
        except (ValueError, AttributeError):
            logging.error(f"Invalid listen address: {args.listen} (expected HOST:PORT)")
            sys.exit(1)

        self.udp = UDPProxy(host, port, self.pool)
        self.tcp = TCPProxy(host, port, self.pool) if args.tcp else None
        self.cover = (
            CoverTraffic(self.pool, args.cover_min, args.cover_max)
            if args.cover
            else None
        )
        self._threads = []

    def _parse_resolvers(self):
        resolvers = []

        if self.args.resolvers_file:
            try:
                with open(self.args.resolvers_file) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            resolvers.append(self._parse_one_resolver(line))
            except FileNotFoundError:
                logging.error(f"Resolvers file not found: {self.args.resolvers_file}")

        for r in self.args.resolver or []:
            resolvers.append(self._parse_one_resolver(r))

        return [r for r in resolvers if r is not None]

    def _parse_one_resolver(self, value):
        value = value.strip()
        if self.doh_mode:
            # DoH mode: resolvers are URLs
            if value.startswith("https://"):
                return value
            # Bare hostname -> assume standard DoH path
            return f"https://{value}/dns-query"
        else:
            # UDP mode: resolvers are IP or IP:PORT
            try:
                if ":" in value:
                    host, port = value.rsplit(":", 1)
                    return (host, int(port))
                return (value, 53)
            except ValueError:
                logging.warning(f"Skipping invalid resolver: {value}")
                return None

    def _probe_resolvers(self):
        """Test all resolvers at startup, keep only working ones."""
        logging.info(f"Probing {len(self.pool.resolvers)} resolvers...")
        query = build_dns_query("google.com")

        def probe(resolver):
            try:
                self.pool.send_query(query, resolver)
                return resolver, True
            except Exception:
                return resolver, False

        working = []
        with ThreadPoolExecutor(max_workers=min(len(self.pool.resolvers), 30)) as executor:
            results = list(executor.map(probe, self.pool.resolvers))

        for resolver, alive in results:
            label = resolver if isinstance(resolver, str) else f"{resolver[0]}:{resolver[1]}"
            if alive:
                working.append(resolver)
                logging.info(f"  \033[32mUP\033[0m   {label}")
            else:
                logging.info(f"  \033[31mDOWN\033[0m {label}")

        if not working:
            logging.warning("No working resolvers found! Keeping all and hoping for the best.")
            return

        logging.info(f"Using {len(working)}/{len(self.pool.resolvers)} working resolvers")
        self.pool = ResolverPool(working, mode=self.pool.mode, doh=self.pool.doh)

    def start(self):
        mode_str = "DoH (HTTPS)" if self.doh_mode else "UDP"
        logging.info(f"DNS Multiplexer starting ({mode_str} upstream)")
        logging.info(f"Distribution mode: {self.args.mode}")
        logging.info(f"Loaded resolvers: {len(self.pool.resolvers)}")

        if not self.args.no_auto_select:
            self._probe_resolvers()
        else:
            for r in self.pool.resolvers:
                logging.info(f"  -> {r}")

        t = threading.Thread(target=self.udp.start, daemon=True)
        t.start()
        self._threads.append(t)

        if self.tcp:
            t = threading.Thread(target=self.tcp.start, daemon=True)
            t.start()
            self._threads.append(t)

        if self.cover:
            self.cover.start()

        if self.args.health_check:
            t = threading.Thread(target=self._health_loop, daemon=True)
            t.start()
            self._threads.append(t)

        if self.args.stats:
            t = threading.Thread(target=self._stats_loop, daemon=True)
            t.start()
            self._threads.append(t)

    def _health_loop(self):
        while True:
            time.sleep(HEALTH_CHECK_INTERVAL)
            self.pool.health_check()
            logging.info(
                f"Health: {self.pool.healthy_count()}/{len(self.pool.resolvers)} resolvers up"
            )

    def _stats_loop(self):
        while True:
            time.sleep(STATS_INTERVAL)
            logging.info(f"Queries handled: {self.udp.query_count}")
            logging.info(f"Resolver stats:\n{self.pool.get_stats_str()}")

    def stop(self):
        logging.info("Shutting down...")
        self.udp.stop()
        if self.tcp:
            self.tcp.stop()
        if self.cover:
            self.cover.stop()

    def wait(self):
        for t in self._threads:
            t.join()


# ─── DNS Scanner ─────────────────────────────────────────────────────────────

BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _rand_label(n=8):
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def _build_query(domain, qtype=1, edns_payload=0):
    """Build DNS query with optional EDNS0 OPT record."""
    txid = random.randint(0, 65535)
    arcount = 1 if edns_payload else 0
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, arcount)
    question = b""
    for label in domain.split("."):
        question += bytes([len(label)]) + label.encode()
    question += b"\x00"
    question += struct.pack("!HH", qtype, 1)
    pkt = header + question
    if edns_payload:
        # OPT RR: name=root, type=OPT(41), class=payload_size, ttl=0, rdlen=0
        pkt += b"\x00" + struct.pack("!HH", 41, edns_payload) + b"\x00\x00\x00\x00\x00\x00"
    return txid, pkt


def _dns_send(data, resolver, timeout=5.0):
    """Send DNS query via UDP and return raw response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(data, resolver)
        resp, _ = sock.recvfrom(4096)
        return resp
    finally:
        sock.close()


def _doh_send(data, url, timeout=5.0):
    """Send DNS query via DoH POST and return raw response."""
    req = Request(url, data=data,
                  headers={"Content-Type": DOH_CONTENT_TYPE, "Accept": DOH_CONTENT_TYPE},
                  method="POST")
    return urlopen(req, timeout=timeout).read()


def _get_rcode(resp):
    if resp and len(resp) >= 4:
        return resp[3] & 0x0F
    return -1


def _get_ancount(resp):
    if resp and len(resp) >= 8:
        return struct.unpack("!H", resp[6:8])[0]
    return 0


def _dotify_base32(payload, max_label=57):
    """Split base32 string into DNS labels of max_label chars."""
    labels = []
    while len(payload) > max_label:
        labels.append(payload[:max_label])
        payload = payload[max_label:]
    if payload:
        labels.append(payload)
    return ".".join(labels)


def scan_resolver(resolver, test_domain, send_fn, doh=False):
    """Run all 7 tunnel compatibility tests on a resolver. Returns dict of results."""
    results = {
        "resolver": resolver,
        "status": "WORKING",
        "latency_ms": 0,
        "ns_support": False,
        "txt_support": False,
        "random_subdomain": False,
        "tunnel_realism": False,
        "edns_support": False,
        "edns_max": 0,
        "nxdomain_correct": False,
        "score": 0,
        "details": "",
    }

    parent_domain = ".".join(test_domain.split(".")[1:]) if "." in test_domain else test_domain

    # ── Test 0: Basic connectivity ──
    try:
        qname = f"{_rand_label()}.{parent_domain}"
        _, pkt = _build_query(qname)
        t0 = time.time()
        resp = send_fn(pkt, resolver)
        results["latency_ms"] = int((time.time() - t0) * 1000)
        if not resp or len(resp) < 12:
            results["status"] = "ERROR"
            return results
    except socket.timeout:
        results["status"] = "TIMEOUT"
        return results
    except Exception as e:
        results["status"] = f"ERROR"
        return results

    score = 0
    details = []

    # ── Test 1: NS delegation + glue ──
    try:
        _, pkt = _build_query(parent_domain, qtype=2)  # NS
        resp = send_fn(pkt, resolver)
        if resp and len(resp) >= 12 and _get_rcode(resp) == 0:
            # Try resolving an NS hostname
            _, pkt2 = _build_query(f"ns.{parent_domain}")
            resp2 = send_fn(pkt2, resolver)
            if resp2 and _get_rcode(resp2) == 0:
                results["ns_support"] = True
                score += 1
                details.append("NS\u2713")
            else:
                details.append("NS\u2717")
        else:
            details.append("NS\u2717")
    except Exception:
        details.append("NS\u2717")

    # ── Test 2: TXT record support ──
    try:
        qname = f"{_rand_label()}.{parent_domain}"
        _, pkt = _build_query(qname, qtype=16)  # TXT
        resp = send_fn(pkt, resolver)
        if resp and len(resp) >= 12:
            results["txt_support"] = True
            score += 1
            details.append("TXT\u2713")
        else:
            details.append("TXT\u2717")
    except Exception:
        details.append("TXT\u2717")

    # ── Test 3: Random nested subdomain ──
    try:
        passed = False
        for _ in range(2):
            qname = f"{_rand_label()}.{_rand_label()}.{test_domain}"
            _, pkt = _build_query(qname)
            try:
                resp = send_fn(pkt, resolver)
                if resp and len(resp) >= 12:
                    passed = True
                    break
            except Exception:
                continue
        results["random_subdomain"] = passed
        if passed:
            score += 1
        details.append("RND\u2713" if passed else "RND\u2717")
    except Exception:
        details.append("RND\u2717")

    # ── Test 4: Tunnel realism (DPI evasion) ──
    try:
        payload = bytes(random.getrandbits(8) for _ in range(100))
        b32 = base64.b32encode(payload).decode().rstrip("=").lower()
        dotified = _dotify_base32(b32)
        qname = f"{dotified}.{test_domain}"
        _, pkt = _build_query(qname, qtype=16)
        resp = send_fn(pkt, resolver)
        if resp and len(resp) >= 12:
            results["tunnel_realism"] = True
            score += 1
            details.append("DPI\u2713")
        else:
            details.append("DPI\u2717")
    except Exception:
        details.append("DPI\u2717")

    # ── Test 5: EDNS0 payload size ──
    try:
        max_edns = 0
        for size in [512, 900, 1232]:
            qname = f"{_rand_label()}.{test_domain}"
            _, pkt = _build_query(qname, qtype=16, edns_payload=size)
            try:
                resp = send_fn(pkt, resolver)
                if resp and len(resp) >= 12 and _get_rcode(resp) != 1:
                    max_edns = size
            except Exception:
                break
        results["edns_max"] = max_edns
        if max_edns > 0:
            results["edns_support"] = True
            score += 1
            details.append(f"EDNS\u2713({max_edns})")
        else:
            details.append("EDNS\u2717")
    except Exception:
        details.append("EDNS\u2717")

    # ── Test 6: NXDOMAIN correctness ──
    try:
        nx_correct = 0
        for _ in range(3):
            qname = f"nxd-{_rand_label()}.invalid"
            _, pkt = _build_query(qname)
            try:
                resp = send_fn(pkt, resolver)
                rcode = _get_rcode(resp)
                if rcode == 3:  # NXDOMAIN
                    nx_correct += 1
                elif rcode == 0 and _get_ancount(resp) == 0:
                    nx_correct += 1  # acceptable - no hijack
            except Exception:
                pass
        if nx_correct >= 2:
            results["nxdomain_correct"] = True
            score += 1
            details.append("NXD\u2713")
        else:
            details.append("NXD\u2717")
    except Exception:
        details.append("NXD\u2717")

    results["score"] = score
    results["details"] = " ".join(details)
    return results


def run_scan(resolvers, test_domain, doh=False, workers=10):
    """Scan all resolvers concurrently and print results."""
    if doh:
        def send_fn(data, resolver):
            return _doh_send(data, resolver)
    else:
        def send_fn(data, resolver):
            return _dns_send(data, resolver)

    print(f"\n{'=' * 78}")
    print(f"  DNS Tunnel Compatibility Scanner")
    print(f"  Test domain: {test_domain}")
    print(f"  Mode: {'DoH (HTTPS)' if doh else 'UDP'}")
    print(f"  Resolvers: {len(resolvers)}")
    print(f"{'=' * 78}\n")

    all_results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_resolver, r, test_domain, send_fn, doh): r
            for r in resolvers
        }
        for future in futures:
            try:
                result = future.result(timeout=30)
                all_results.append(result)

                label = result["resolver"] if isinstance(result["resolver"], str) \
                    else f"{result['resolver'][0]}:{result['resolver'][1]}"

                if result["status"] == "WORKING":
                    status = f"\033[32mWORKING\033[0m"
                elif result["status"] == "TIMEOUT":
                    status = f"\033[33mTIMEOUT\033[0m"
                else:
                    status = f"\033[31m{result['status']}\033[0m"

                score_str = f"{result['score']}/6"
                print(f"  {label:<45} {status:<18} {result['latency_ms']:>4}ms  "
                      f"Score: {score_str}  {result['details']}")
            except Exception as e:
                print(f"  {futures[future]}: scan error: {e}")

    # Summary
    working = [r for r in all_results if r["status"] == "WORKING"]
    timeouts = [r for r in all_results if r["status"] == "TIMEOUT"]
    errors = [r for r in all_results if r["status"] not in ("WORKING", "TIMEOUT")]

    print(f"\n{'─' * 78}")
    print(f"  Total: {len(all_results)}  |  "
          f"\033[32mWorking: {len(working)}\033[0m  |  "
          f"\033[33mTimeout: {len(timeouts)}\033[0m  |  "
          f"\033[31mError: {len(errors)}\033[0m")

    if working:
        best = sorted(working, key=lambda r: (-r["score"], r["latency_ms"]))
        print(f"\n  Best resolvers for tunneling:")
        for r in best[:5]:
            label = r["resolver"] if isinstance(r["resolver"], str) \
                else f"{r['resolver'][0]}:{r['resolver'][1]}"
            print(f"    {label:<45} Score: {r['score']}/6  {r['latency_ms']}ms  {r['details']}")

    print()
    return all_results


def main():
    parser = argparse.ArgumentParser(
        description="DNS Multiplexer Proxy - Middle proxy for DNSTT/NoizDNS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Plain DNS upstream (default)
  %(prog)s -r 8.8.8.8 -r 1.1.1.1 -r 9.9.9.9

  # DoH upstream (when outbound port 53 is blocked)
  %(prog)s --doh
  %(prog)s --doh -r https://dns.google/dns-query -r https://cloudflare-dns.com/dns-query

  # Full setup
  %(prog)s --doh --cover --stats --health-check --tcp

  # Scan resolvers for tunnel compatibility
  %(prog)s --scan --scan-domain t.example.com
  %(prog)s --scan --doh --scan-domain t.example.com
""",
    )

    parser.add_argument(
        "--listen", "-l", default="0.0.0.0:53",
        help="Listen address:port (default: 0.0.0.0:53)",
    )
    parser.add_argument(
        "--resolver", "-r", action="append",
        help="Upstream resolver: IP[:PORT] or DoH URL (can repeat)",
    )
    parser.add_argument(
        "--resolvers-file", "-f",
        help="File with resolver list (one per line)",
    )
    parser.add_argument(
        "--doh", action="store_true",
        help="Use DoH (DNS over HTTPS) for upstream queries (bypasses port 53 blocks)",
    )
    parser.add_argument(
        "--no-auto-select", action="store_true",
        help="Skip startup probe, use all resolvers without testing them first",
    )
    parser.add_argument(
        "--mode", "-m", choices=["round-robin", "random"], default="round-robin",
        help="Query distribution mode (default: round-robin)",
    )
    parser.add_argument(
        "--tcp", action="store_true",
        help="Also listen for TCP DNS queries",
    )
    parser.add_argument(
        "--cover", action="store_true",
        help="Generate cover traffic (legitimate DNS queries)",
    )
    parser.add_argument(
        "--cover-min", type=float, default=5.0,
        help="Min cover traffic interval seconds (default: 5)",
    )
    parser.add_argument(
        "--cover-max", type=float, default=15.0,
        help="Max cover traffic interval seconds (default: 15)",
    )
    parser.add_argument(
        "--health-check", action="store_true",
        help="Enable periodic resolver health checks",
    )
    parser.add_argument(
        "--stats", action="store_true",
        help="Log query statistics periodically",
    )
    parser.add_argument(
        "--scan", action="store_true",
        help="Scan resolvers for DNS tunnel compatibility (like SlipNet scanner)",
    )
    parser.add_argument(
        "--scan-domain",
        help="Tunnel domain to test against (required for --scan, e.g. t.example.com)",
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO)",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Scan mode
    if args.scan:
        if not args.scan_domain:
            parser.error("--scan requires --scan-domain (e.g. --scan-domain t.example.com)")

        resolvers = []
        if args.resolvers_file:
            try:
                with open(args.resolvers_file) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            if args.doh:
                                resolvers.append(line if line.startswith("https://")
                                                 else f"https://{line}/dns-query")
                            else:
                                if ":" in line:
                                    h, p = line.rsplit(":", 1)
                                    resolvers.append((h, int(p)))
                                else:
                                    resolvers.append((line, 53))
            except FileNotFoundError:
                pass

        for r in args.resolver or []:
            if args.doh:
                resolvers.append(r if r.startswith("https://") else f"https://{r}/dns-query")
            else:
                if ":" in r:
                    h, p = r.rsplit(":", 1)
                    resolvers.append((h, int(p)))
                else:
                    resolvers.append((r, 53))

        if not resolvers:
            if args.doh:
                resolvers = list(DEFAULT_DOH_RESOLVERS)
            else:
                parser.error("No resolvers specified. Use -r or -f.")

        run_scan(resolvers, args.scan_domain, doh=args.doh)
        sys.exit(0)

    # Proxy mode
    mux = DNSMultiplexer(args)

    def on_signal(sig, frame):
        mux.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    mux.start()
    mux.wait()


if __name__ == "__main__":
    main()
