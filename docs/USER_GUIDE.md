# SlipNet — Complete User Guide

> Official channel: [@SlipNet_app](https://t.me/SlipNet_app)
> Source code: https://github.com/anonvector/SlipNet
> SlipNet is **NOT** on Google Play, the App Store, or any other marketplace. Only download it from the official channel or GitHub.

---

## Table of Contents

1. What SlipNet is — and why it exists
2. Supported tunnel types
3. Editions: Full vs. Lite
4. Installing the APK
5. You need a server (use SlipGate)
6. Adding your first profile
7. Connecting and disconnecting
8. The DNS Resolver Scanner
9. Profile Chains — combining tunnels
10. Settings reference
11. Per-tunnel quick reference
12. Troubleshooting
13. Sharing & backups
14. Donations
15. Stay safe

---

## 1. What SlipNet is — and why it exists

SlipNet is a free, **source-available** anti-censorship tool. The main client is an Android app, with a matching command-line client for macOS, Linux, and Windows. It tunnels your internet traffic through different protocols — DNS, QUIC, SSH, HTTPS, VLESS, or Tor — so you can reach the open internet even on networks that block, throttle, or deep-packet-inspect normal traffic.

Unlike a typical VPN that ships with a single protocol, SlipNet offers many **transports** so you can pick the one that survives on whatever network you're stuck on:

- If your ISP only lets DNS traffic out, use a DNS tunnel — DNSTT, NoizDNS, or VayDNS.
- If only HTTPS gets through, use NaiveProxy or VLESS fronted through a CDN like Cloudflare.
- If your network does deep traffic inspection and recognises tunnel-shaped flows, layer SSH on top of any of the above for zero DNS leaks and an extra layer of encryption.
- In the worst case, fall back to Tor with Snowflake, obfs4, or Meek bridges (Full edition only).

SlipNet sits in the same family as projects like [Tor](https://torproject.org), [Psiphon](https://psiphon.ca), and [Outline VPN](https://getoutline.org), but with one critical difference: SlipNet is **pure client software**. There is no central network or company-run infrastructure — you either run your own server (a few minutes with [SlipGate](https://github.com/anonvector/slipgate)) or get a config from someone you trust. That model has three real advantages:

- **Privacy.** Your traffic exits through a server you or someone you know controls — not an unknown company's exit node.
- **Resilience.** With no central infrastructure to filter, blocking the project is impractical. If a single server gets blocked, swap the IP and update one DNS record.
- **Flexibility.** You choose the protocol, the CDN, the domain, even the country your traffic exits from — control that no commercial VPN gives you.

The full source code lives on GitHub under a **source-available** license — readable, studyable, and open to contributions, but not licensed for redistribution or republishing on app stores. SlipNet is **not** on Google Play, the App Store, or any other marketplace; the only official sources are the [@SlipNet_app](https://t.me/SlipNet_app) Telegram channel and the project's GitHub repository.

---

## 2. Supported tunnel types

| Tunnel | Protocol | What it does | Best for |
|--------|----------|--------------|----------|
| **DNSTT** | DNS (KCP + Noise) | Tunnels traffic inside DNS queries | Networks that only allow DNS |
| **NoizDNS** | DNS (KCP + Noise) | DNSTT with DPI evasion (base36/hex, CDN prefix stripping) | Heavily inspected networks |
| **VayDNS** | DNS (KCP + Curve25519) | Optimized DNS tunnel; tunable record types, QNAME length, rate limit | Advanced users on flaky DNS paths |
| **Slipstream** | QUIC | High-performance QUIC tunnel | Fast, clean networks |
| **SSH** | SSH | Standalone SSH tunnel | Simple, encrypted, leak-proof |
| **NaiveProxy** | HTTPS (Caddy + Chromium TLS) | HTTPS with authentic Chrome TLS fingerprint | DPI bypass over HTTPS |
| **VLESS** | WebSocket (over TLS or plain) | VLESS-over-WebSocket via CDN (e.g. Cloudflare) | CDN fronting, very common in Iran |
| **DOH** | DNS over HTTPS | Encrypts DNS only — no traffic tunnel | Bypassing DNS-only blocks |
| **Tor** | Tor + Snowflake/obfs4/Meek | Anonymity network | Strong anonymity |
| **+ SSH variants** | (DNSTT/NoizDNS/VayDNS/Slipstream/NaiveProxy/VLESS) + SSH | Adds SSH on top — zero DNS leaks, extra encryption | Maximum security |

**How to choose:**

- New user, no idea? → **DNSTT** (default).
- DPI is aggressive? → **NoizDNS** or **NoizDNS + SSH**.
- Need to fly under Cloudflare? → **VLESS** or **NaiveProxy**.
- Want raw speed on a clean link? → **Slipstream**.
- Need anonymity? → **Tor** (Full edition only).

---

## 3. Editions: Full vs. Lite

SlipNet ships in two editions — the difference is the size of the APK and which protocols are bundled.

| Feature | Full | Lite |
|---------|:----:|:----:|
| DNSTT, NoizDNS, VayDNS | ✓ | ✓ |
| Slipstream (QUIC) | ✓ | ✓ |
| SSH | ✓ | ✓ |
| DoH | ✓ | ✓ |
| VLESS | ✓ | ✓ |
| **NaiveProxy** | ✓ | — |
| **Tor (Snowflake / obfs4 / Meek)** | ✓ | — |
| Approx. APK size | ~50 MB | ~20 MB |

**Full** is the default recommendation. **Lite** is for slow connections, low-storage phones, or when Tor and NaiveProxy aren't needed.

---

## 4. Installing the APK

1. Open the official Telegram channel [@SlipNet_app](https://t.me/SlipNet_app) or the GitHub Releases page.
2. Download the APK that matches your phone's CPU. Most modern phones are `arm64-v8a`. If you don't know, download the **universal** APK.
3. On your phone: **Settings → Security → Install unknown apps** → allow your browser/Telegram to install APKs.
4. Tap the downloaded APK and install.
5. Open SlipNet. On first launch, Android will ask for **VPN permission** — tap **OK**.
6. Recommended one-time setup: **Settings → Battery optimization → Don't optimize SlipNet**, so Android doesn't kill it in the background.

> ⚠️ If you find SlipNet on Google Play, App Store, or any other store, it is **not** ours. Don't install it.

---

## 5. You need a server — use SlipGate

SlipNet is a *client*. To use it you must connect to a **server** running a compatible tunnel.

The official, supported way to run a server is **SlipGate** — a one-command Linux installer that sets up every protocol SlipNet supports.

> https://github.com/anonvector/slipgate

A separate operator guide for SlipGate is available alongside this document. In short: get a $5/month VPS, point a domain at it, run a single install command, create a user, and SlipGate prints a `slipnet://` link you paste straight into the app.

If you don't run your own server, you can:
- Get a `slipnet://` link from a friend who runs SlipGate, or
- Use a public test link sometimes shared in [@SlipNet_app](https://t.me/SlipNet_app).

---

## 6. Adding your first profile

There are three ways to add a server profile.

### A) Paste a `slipnet://` link (easiest)

1. Open SlipNet → tap the **+** button at the bottom right.
2. Choose **Import from URI**.
3. Paste the `slipnet://...` link.
4. Done — the profile appears in your list.

### B) Import a JSON file

If a friend exported their profiles (encrypted or plain JSON):

1. Tap the menu (⋮) on the home screen → **Import Profiles**.
2. Select the `.json` file.
3. If it's encrypted, enter the password they shared.

### C) Build a profile manually

Useful when your provider gives you raw values (domain + key) instead of a URI.

1. Tap **+** → **Add Profile**.
2. Give it a **Name**.
3. Pick a **Tunnel Type** (the form changes per type — see §11 for what each one needs).
4. Fill in the required fields.
5. Tap **Save**.

---

## 7. Connecting and disconnecting

1. Tap a profile in the list to select it (a checkmark appears).
2. Tap the big **Connect** button at the bottom.
3. The first time, Android shows a VPN-permission dialog → **OK**.
4. When the icon turns green and you see live upload/download numbers, you're connected. All your traffic now flows through the tunnel.

To disconnect, tap **Connect** again. To switch profiles, disconnect first, pick a different profile, then reconnect.

**Quick toggle without opening the app:**
- Pull down the notification shade → tap the **SlipNet Quick Settings tile** (you may need to add it from the tile picker the first time).
- Or use the **home-screen widget** for one-tap connect/disconnect.

**Live ping test:** while a profile is selected, tap **Real Ping** or **Simple Ping** to measure latency. **Sort by Ping** orders the profile list fastest-first.

---

## 8. The DNS Resolver Scanner

DNS-tunnel profiles (DNSTT, NoizDNS, VayDNS) only work through resolvers that obey a few RFC behaviours and don't tamper with replies. Many ISP resolvers fail one or more of those checks — they hijack NXDOMAIN, strip EDNS, refuse long names, or block tunnel-shaped traffic at DPI. The **Scanner** finds resolvers that pass.

Open: **menu → DNS Resolver Scanner**.

The scanner has four big things you control:

1. **Scan Mode** — what kind of test to run
2. **Configuration** — test domain, ports, timeouts, parallelism
3. **IP source** — where the candidate IPs come from
4. **Results & Apply** — review and push the survivors back into your profile

---

### 8.1. Scan modes

A toggle at the top picks one of four modes. Each is a different trade-off between speed, depth, and certainty.

#### Simple
*"Scans DNS resolvers and automatically tests each one through the tunnel. Only resolvers that pass the tunnel test are shown."*

The one-tap mode for everyone. The scanner runs the DNS-compatibility probe **and** an end-to-end tunnel test in one pipeline, and only displays resolvers that genuinely deliver traffic. Use this if you don't want to think.

Requires a profile with a valid public key (so the tunnel test has a real server to talk to).

#### Advanced
*"Scan DNS resolvers first, then optionally run tunnel test separately."*

The classic two-stage flow. Stage 1 is the DNS probe and gives every resolver a 0–6 score (see §8.5). You can review results, sort, filter, and then optionally trigger an E2E tunnel test on resolvers that passed the score threshold. Use this when you want to inspect the probe details, or when you don't have a profile yet.

#### E2E
*"Tests each resolver directly through the tunnel, skipping DNS compatibility checks. Slower but tests real connectivity."*

Skips the DNS probe entirely. For each candidate IP it just opens a real tunnel and tries an HTTP request. Use this when you already have a list of "known DNS-tunnel-capable" IPs and you only want to know which ones currently reach your specific server fast.

#### Prism
*"Server-verified scan: only resolvers that cryptographically prove they reach your specific server are shown. Requires SlipGate installed on your server."*

The strongest mode. Sends HMAC-authenticated probes that only a real SlipGate server can sign correctly, so a resolver that "works" but actually delivers traffic to an attacker's middlebox will fail the check. Each resolver is probed N times; resolvers that get ≥ *threshold* signed responses pass. Use this when you suspect transparent-proxy interception or want defense against tunnel hijacking.

Only available when your selected profile has a valid public key and your server runs [SlipGate](https://github.com/anonvector/slipgate).

---

### 8.2. Configuration panel

These fields appear above the scan button. Most have sane defaults — only touch them if a scan is failing.

**Common to Simple / Advanced**
- **Test Domain** — the name the probe will query. Use *your tunnel's domain* (e.g. `t.example.com`); a resolver that can route long random subdomains under it is the one that can carry a real tunnel. Locked profiles fall back to the profile's own domain.
- **Port** — usually `53`. Override if your server runs on a non-standard DNS port.
- **Timeout (ms)** — per-resolver timeout for the DNS probe. Default 3000. Drop to 1500 if your candidate list is huge and full of dead IPs.
- **Workers** — parallel probes. Default 50. Lower it on flaky links to avoid drops.

**E2E-only**
- **Resolver Port** — port the resolver listens on (53 unless overridden).
- **E2E Timeout** — per-resolver tunnel-test timeout. Default 15000 ms.
- **E2E Concurrency** — parallel tunnel tests. 1–10. **Slipstream max 1** because QUIC tunnels can't share a port.
- **Test URL** — what the tunnel will fetch to prove connectivity. Default `http://www.gstatic.com/generate_204` (returns 204 No Content — small, fast, doesn't depend on DNS resolution inside the tunnel).
- **Full Verification** — when on, fetches the test URL through the live tunnel; when off, only confirms the tunnel handshake completes.

**Prism-only**
- **Probes** — number of HMAC-signed requests sent to each resolver. More probes = stronger statistical confidence, slower scan. Default 5.
- **Pass threshold** — minimum number of probes that must come back correctly signed. Default 2.
- **Timeout (per resolver)** — overall budget split across probes. The app rejects settings where per-probe time would drop below 200 ms.
- **Response size** — bytes the server should pad responses to (0 = server default). Useful if your server is configured for a specific reply size.
- **Pre-filter dead resolvers** — runs a quick DNS check first to drop unresponsive IPs before spending probe budget on them. Recommended for large lists.

**Scan Transport (Advanced and Simple only)** — `UDP`, `TCP`, or `Both`. **Both** runs UDP first, then retries only the resolvers that didn't pass over TCP. Useful in networks where UDP DNS is rate-limited or filtered, since some resolvers respond fine over TCP. Each result shows badges (`UDP`, `TCP`) for which transport it survived.

---

### 8.3. IP source panel

Tabs across the bottom decide *where the candidate IPs come from*. Pick exactly one source per scan.

- **Default** — the app's built-in curated list of resolvers known to work historically. Smallest, fastest scan; good first attempt.
- **Import** — load IPs from a file (`.txt`, one per line or comma-separated). Use this to scan a list someone shared, or your own previous results.
- **Country** — generates random IPs from a chosen country's address allocations. Pick a country and a sample count (default 2000, max 100 000). For Iran users this is often the goldmine — domestic resolvers usually beat foreign ones for tunnel purposes because local DPI doesn't bother inspecting them as aggressively.
- **Custom** — paste a CIDR (`5.144.0.0/14`), an IP range (`5.144.0.1-5.147.255.254`), comma-separated IPs, or a single IP. The preview counter shows how many IPs you'd be scanning before you commit.
- **IR DNS Ranges** — Iranian ISP DNS allocations grouped by `/8` octet. Pick which `/8` groups to include (the count badge shows total IPs per group). Heavier than IR DNS Lite but more thorough.
- **IR DNS Lite** — a pre-curated subset of Iranian DNS ranges, smaller and faster than the full IR DNS list. Good default for Iranian users.
- **Recent DNS** *(button at the bottom)* — replays the IPs from the last scan, useful for iterating on settings without regenerating the candidate set.
- **Load Last Scan IPs** — pulls back resolvers that already passed in a previous run (separates "Working IPs" from "E2E Passed IPs" so you can re-run only the proven set).

Toggles that apply to most sources:
- **Shuffle** — randomise scan order. Default on. Helps avoid hot-spotting one ISP.
- **Expand neighbours** — when scanning a custom range, also probe a few IPs on either side of any hit, since DNS resolvers often live in clusters.

---

### 8.4. Results & Apply

After the scan finishes, tap **View Results**. Each resolver row shows:

- The resolver IP and the score (0–6) from the DNS probe.
- A breakdown badge: `NS✓ TXT✓ RND✓ DPI✓ EDNS✓(1232) NXD✓` — see §8.5.
- For Simple/E2E modes: tunnel setup time, HTTP latency, total round-trip.
- For Prism: `Probes 4/5` (passed/total) and a `Verified` badge.
- Transport badges (`UDP`, `TCP`) showing which the resolver survived.
- `WORKING` / `CENSORED` / `TIMEOUT` / `ERROR` status.

You can:
- **Sort** by score, by latency, or by E2E success.
- **Filter** by passed-probe count (Prism), by score range (Advanced), or by "all working".
- **Search** by IP substring.
- **Copy** or **Export** visible IPs (E2E-passed only / Stage-1 working only / your selection).
- **Re-test Tunnel** on a single result — useful if the network just changed.
- **Apply Selected** — pushes the selected resolvers into the active profile (max 8). The next time you connect, those resolvers are used.

You can resume a scan that was interrupted (the app prompts on next entry). E2E tests can be paused/continued mid-run.

---

### 8.5. The 0–6 score, decoded

The DNS-compatibility score is the count of these six probes that passed. Each is one binary point.

| Probe | What it tests | Why it matters |
|-------|---------------|----------------|
| **NS** | Resolver follows `NS` records and returns A records for the parent zone | Tunnel servers are typically delegated subdomains; a resolver that ignores NS delegation can't even find the tunnel server |
| **TXT** | Resolver returns TXT records | DNSTT/NoizDNS/VayDNS encode return data in TXT (or other types — see VayDNS settings); broken TXT = no downstream traffic |
| **RND** | Resolver actually queries upstream for random subdomains it has never seen | Some "smart" resolvers cache aggressively or short-circuit unknown names — a DNS tunnel makes up a fresh subdomain per query, so this must work |
| **DPI** | A `dnstt`-style long base32-encoded TXT query gets through | Detects DPI boxes that fingerprint tunnel-shaped DNS by entropy/length/record-type; if this fails, your queries will be dropped silently |
| **EDNS** | Resolver supports EDNS0 large responses (>512 bytes); badge shows max payload (512 / 900 / 1232) | Tunnel throughput depends on response size — 1232 is the dnsflagday.net target; resolvers stuck at 512 will be brutally slow |
| **NXD** | Resolver returns proper `NXDOMAIN` for non-existent names instead of hijacking to a parking IP | Hijacking resolvers spoof answers, which corrupts the tunnel framing — a hijacker scores `NXD✗` and is unusable |

A score of **6** is fully tunnel-compatible. **5** is usually fine — the missing point is often EDNS payload size, which only hurts speed. **3 or below** is rarely worth using. The Pass threshold field lets you set the minimum.

---

### 8.6. Practical recipes

- **Iranian user, default profile, just want to connect**: Simple mode → IR DNS Lite source → Start.
- **Iranian user, exhaustive search**: Simple mode → IR DNS Ranges source → pick all groups → bump sample count to 5000.
- **Foreign tunnel-tester**: Advanced mode → Country source → set country → score threshold 5.
- **You suspect your ISP is intercepting**: Prism mode → IR DNS Lite → 8 probes / threshold 5.
- **You already have a working list, just verify speed**: E2E mode → Import that list → high concurrency.
- **UDP DNS is being rate-limited**: any mode → Scan Transport = `Both`.

---

## 9. Profile Chains — combining tunnels

The **Chains** tab lets you stack multiple profiles end-to-end. Example chains:

- `NoizDNS → SSH → destination` — DPI-resistant transport with SSH on top, zero DNS leaks.
- `VLESS (Cloudflare) → SSH` — CDN fronting plus encrypted final hop.
- `Tor → NaiveProxy` — anonymity plus HTTPS exit.

**Build a chain:**
1. Open the **Chains** tab.
2. Tap **+ New Chain**.
3. Add profiles in order — first hop at the top, last hop at the bottom.
4. Save and select the chain like any normal profile.

When you connect, the app validates that the chain is consistent (compatible transports, no loops) and streams the chain as one tunnel.

---

## 10. Settings reference

Open **Settings** to tune the app.

**Connection**
- **Auto-connect on boot** — reconnect when the phone restarts.
- **Auto-reconnect** — reconnect if the VPN drops unexpectedly.
- **Auto-disconnect after** — set an idle timeout.
- **Block all if VPN drops** — kill switch (no leaks).
- **VPN MTU** — lower it (e.g., 1280) if some sites won't load.
- **DNS Workers** — fewer = more stable on restricted networks; "per-query" creates a fresh connection per lookup.
- **Disable QUIC** — forces apps to use TCP; often noticeably faster over a tunneled link.

**Routing**
- **Split Tunneling** — choose which apps use the VPN (allowlist or bypass).
- **Domain Routing** — only specific domains go through the tunnel.
- **Geo-bypass** — route traffic to IPs/sites in your selected country *outside* the VPN, so local websites stay fast and unaffected by the tunnel.
- **Bypass VPN** — let certain apps skip the VPN entirely.
- **Append HTTP Proxy to VPN** — also expose a local HTTP proxy.

**DNS**
- **Global DNS Resolvers** — override resolvers for all profiles.
- **Remote DNS Server** — what runs on the far side of the tunnel.
- **DNS Resolver Scanner** — see §8.

**Security**
- **SSH Cipher** — prefer AES-128-GCM, ChaCha20, or AES-128-CTR (legacy).
- **Bandwidth Limit** — cap upload/download.
- **Hotspot mode** — share the tunnel with other devices over Wi-Fi.

**Appearance**
- **Dark mode** — Dark / AMOLED Dark / Auto.

**Diagnostics**
- **Debug logging** — verbose logs for support.
- **Device ID / IP** — copy for support requests.
- **Check for updates** — pulls the latest release.

---

## 11. Per-tunnel quick reference

What each tunnel type asks for when you build a profile manually.

### DNSTT / NoizDNS
- **Domain** — your tunnel subdomain, e.g., `t.example.com`
- **Public Key** — server's Curve25519/Noise key (hex)
- **DNS Transport** — UDP / TCP / DoT / DoH
- **DNS Resolvers** — IPs of resolvers to send queries through
- *NoizDNS:* **Stealth Mode** — slower but harder to detect

### VayDNS
- Domain + Public Key (as above)
- **Record Type** — TXT / CNAME / A / AAAA / MX / NS / SRV
- **Max QNAME Length** — wire size of each query
- **Rate Limit (RPS)** — outgoing queries per second
- **Idle Timeout / Keep-Alive / UDP Timeout**
- **ClientID Size** — must match server (default 2; 8 in DNSTT-compat mode)

### Slipstream
- Domain + Public Key
- **Congestion Control** — BBR / DCUBIC
- **Keep-Alive Interval**
- **Authoritative Mode**, **GSO**

### SSH (standalone or as the last hop)
- **SSH Host / Port** (default 22)
- **Username + Password** *or* **Private Key** (with passphrase)
- **Cipher** — AES-128-GCM / ChaCha20 / AES-128-CTR

SSH transport options (work with any SSH-based tunnel):
- **SSH over TLS** — wrap SSH in TLS with custom SNI (domain fronting).
- **HTTP CONNECT proxy** — route through an HTTP CONNECT proxy with custom Host header.
- **SSH over WebSocket** — `ws://` or `wss://` with custom path & Host (Cloudflare-friendly).
- **SSH Payload** — send raw bytes before the SSH handshake to disguise it. Supports `[host]`, `[port]`, `[crlf]`, `[cr]`, `[lf]`.

### NaiveProxy
- **Server hostname** + **port** (usually 443)
- **Proxy username / password**

### VLESS
- **UUID** — your VLESS user ID (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
- **Domain** — the hostname behind the CDN; used as TLS SNI and WS Host
- **Security** — `tls` (recommended) or `none`
- **Transport** — WebSocket only (raw TCP isn't supported in the app — VLESS in SlipNet is positioned as a CDN-fronted tunnel)
- **WS Path** — e.g., `/`, `/vless`
- **CDN IP / Port** — a Cloudflare clean IP if you're fronting through CF (otherwise direct server IP, port 443)
- **TLS SNI** — what gets put in the ClientHello (must match the CDN cert when using CDN routing)
- **SNI Fragmentation** — TLS DPI-evasion: split / pad the ClientHello (try this if your ISP detects VLESS)
- **Header obfuscation** *(WS only)* — randomized browser-like headers

### SOCKS5 (chain to a remote SOCKS5 proxy)
- **Remote SOCKS5 host / port**
- **Username / password** (optional, RFC 1929)
- **DNS server** for in-tunnel DNS-over-TCP (default `8.8.8.8`)

#### ⚠️ Why SOCKS5 can show "Connected" but still not work

SlipNet's SOCKS5 mode is a **passthrough** — it just opens a local listener on your phone and forwards every downstream request to the remote SOCKS5 proxy. There is **no upfront end-to-end probe** of the upstream. The "Connected" status only confirms two things:

1. The local SOCKS5 listener bound on your phone, and
2. Some downstream connection completed the SOCKS5 handshake (CONNECT + auth) with the upstream.

It does **not** confirm that the upstream proxy can actually reach the open internet. The proxy may be silently dropping outbound traffic, returning forged CONNECT replies, sitting behind a cloud firewall that only allows internal CIDRs, or itself behind a censored uplink — and SlipNet has no way to tell from the SOCKS5 protocol alone, because SOCKS5 carries **no server identity, no end-to-end key exchange, and no liveness signal**.

#### SSH vs. SOCKS5

Bringing up an SSH tunnel requires every one of these steps to succeed before the instance reports itself connected:

- TCP connect to the SSH endpoint
- SSH version banner exchange
- Key exchange (ECDH/DH) — produces a shared session key
- User authentication (password or pubkey) — verified by the server
- A real channel opened over the encrypted session

If any step fails, SSH never goes green. So when SSH says "connected", an encrypted, authenticated channel really exists and is actually carrying bytes. That's why **SSH-based tunnels fail loudly** when something is wrong, while plain SOCKS5 can show a falsely green status.

| | SOCKS5 | SSH |
|---|---|---|
| Server identity check | None | Implicit via auth (and host-key, if pinned) |
| End-to-end key exchange | None | Yes (ECDH/DH) |
| "Connected" implies traffic flows | No | Yes |
| Encryption to the server | No (plaintext to the proxy) | Yes |
| Detects MITM / silent drops | No | Yes |

> **Same symptom on DNS tunnels.** DNSTT, NoizDNS, and VayDNS in their **standalone form** (without the `+ SSH` wrapper) expose a local SOCKS5 listener as their downstream interface. The DNS tunnel itself *is* authenticated end-to-end (Noise / Curve25519 handshake, so the tunnel link is real), but what happens *after* the server-side terminator — the actual outbound to the open internet — is plain SOCKS5/forwarding with no end-to-end check. So a DNSTT/NoizDNS/VayDNS profile can also show **"Connected" while real traffic silently fails** if the server's outbound forwarder is broken or geo-restricted. The **`+ SSH` variants** (DNSTT+SSH, NoizDNS+SSH, VayDNS+SSH) fix this by running a real SSH session *through* the DNS tunnel — the SSH handshake only completes when the server can genuinely carry traffic to its destination, restoring the liveness guarantee.

**Practical takeaway:**

- Treat SOCKS5 mode as a **transport adapter** for a proxy you already trust — not as a tunnel test. If the proxy is broken or geo-restricted, you'll see green with zero traffic flowing.
- For a real anti-censorship tunnel, prefer **SSH** or one of the SSH-wrapped variants (NoizDNS+SSH, Slipstream+SSH, VLESS+SSH, NaiveProxy+SSH, …) — they fail loudly when something is wrong.
- If you must run plain SOCKS5, layer **SSH on top** when the upstream supports it — the `+ SSH` family treats the upstream as a transport and runs a real SSH session through it, restoring liveness and authentication guarantees.

### DOH
- **DoH Server URL** — e.g., `https://cloudflare-dns.com/dns-query`
- *(DOH only encrypts DNS — your traffic still goes out normally.)*

### Tor (Full edition)
- **Bridge type** — Snowflake / obfs4 / Meek / Direct / Custom bridge lines
- **Auto-detect Best Bridge** — lets the app pick

---

## 12. Troubleshooting

| Symptom | Try this |
|---------|----------|
| Can't connect at all | Run the **Scanner**, replace resolvers; switch DNS Transport (UDP → DoT → DoH); try **NoizDNS** instead of DNSTT |
| Connects, then drops in seconds | Lower **VPN MTU** (1280), set **DNS Workers = 1** or *per-query* |
| Connected but no internet | Disable **QUIC** in settings; toggle **Auto-reconnect** |
| Phone kills SlipNet in background | Settings → **Battery optimization** → don't optimize SlipNet |
| YouTube / streaming buffers | Enable **Disable QUIC**; lower **Max Query Size** on DNS tunnels; try **Slipstream** or **VLESS** |
| Heavy DPI environment | Use **NoizDNS + SSH**, **VLESS + SNI Fragmentation**, or **Tor + Snowflake** (Full) |
| VLESS times out via Cloudflare | Set **CDN IP** to a known clean Cloudflare IP; verify **TLS SNI** matches your CF cert |
| SOCKS5 says "Connected" but no internet | Upstream proxy isn't actually reaching the open internet — SOCKS5 has no end-to-end check. Test the proxy independently, or wrap it with SSH (use a `+ SSH` variant) so failure becomes visible. |
| Need to share logs with support | Settings → **Debug logging** → reproduce the issue → **Export logs** |

---

## 13. Sharing & backups

- **Share a single profile**: open it → menu → **Export** → choose `slipnet://` URI or JSON.
- **Export everything**: home menu → **Export All Profiles** (plain) or **Export All (Encrypted)** with a password.
- **Backup your settings**: Settings → menu → **Export Settings**.
- **Share the APK** with friends via Bluetooth from the home menu (useful during internet shutdowns).

### Config URI types

SlipNet exports use three URI schemes. They are **not** equivalent — the security model is very different.

| Scheme | What it is | Encryption key |
|---|---|---|
| `slipnet://` | Plain base64-encoded profile | None — anyone can decode it |
| `slipnet-enc://` | Single **locked** profile (single-recipient share) | App-baked key from SlipNet's native library |
| `slipnet-bundle-enc://` | Multi-profile **password-encrypted** backup bundle | Derived from your password |

**`slipnet://`** — readable by anyone who can run base64. Use only for trusted recipients.

**`slipnet-enc://`** — produced when you export a single profile with a lock (password, optional expiration date, optional device-binding, hidden resolvers, no-resharing). The payload is AES-256-GCM encrypted, **but the AES key is baked into the SlipNet app itself**, not derived from your password. The password you set is checked by the recipient's app — it controls **how** the recipient can use the profile (use only, no editing, expires on date X, bound to one device, resolvers hidden). It does **not** keep your config secret from anyone with the SlipNet APK. Treat it as a **sharing-control** mechanism, not real confidentiality.

**`slipnet-bundle-enc://`** — produced by **Export All (Encrypted)**. This one *is* real password-derived encryption (your password is the key material). Suitable for off-device backups.

### ⚠️ Even encrypted configs are unsafe to post publicly

Encrypting the config bytes does **not** protect the **identity** of your server, domain, or CDN host. The moment a `slipnet-enc://` link reaches a public channel:

- Anyone with the SlipNet APK can decrypt it and read the domain, IP, SNI, CDN host, and credentials.
- Censors monitor public channels for new configs and add the domains/IPs to their blocklists within hours.
- The domain itself becomes a permanent blocklist target — encryption cannot undo that.

This is doubly serious if you bought your **VPS or domain inside the country whose censorship you're trying to bypass**:

- Local registrars and hosting providers can be **compelled to reveal ownership, suspend the service, or hand over logs**.
- Domains under a national TLD (e.g. `.ir`, `.cn`, `.ru`, or any TLD operated under the same jurisdiction) can be seized administratively, regardless of how strong your tunnel encryption is.
- A VPS or domain traceable to a person inside that country exposes the **operator**, not just the config.

Rules of thumb:

- For wider distribution, host on a **VPS bought outside the country** with a domain registered through an **off-shore registrar**. On that same VPS, **enable Warp from inside SlipGate** so the server's egress goes through Cloudflare Warp and the real VPS IP is never exposed downstream.
- Share configs **privately** (1-to-1, end-to-end-encrypted chat) — not in groups, not on websites, not pinned in channels.
- Use `slipnet-enc://` lock features (expiration, device-bind, hide-resolvers, no-resharing) to **slow down** abuse, not to make a config publicly shareable.

> ⚠️ A `slipnet://` link contains your credentials. Never post yours in a public group.
> ⚠️ A `slipnet-enc://` link is **not** safe to post publicly either — the SlipNet app can decrypt it. The lock controls usage, not secrecy. The encryption protects the *credentials* on the wire; it does **not** protect the *domain identity* once the link is in the open.

---

## 14. Donations

Development is unpaid. If SlipNet helps you, donation addresses (BEP-20 / ERC-20 / Arbitrum, Monero, etc.) are kept up to date in the project README on GitHub: <https://github.com/anonvector/SlipNet#donations>

---

## 15. Stay safe

- Only download SlipNet from the **official Telegram channel** or **GitHub**.
- Verify the APK signature if you're paranoid (signing fingerprint is on the GitHub release page).
- Never share your `slipnet://` link with strangers.
- Use **encrypted export** for backups.
- Verify your server is genuine with **Prism** (server-verified scan) — works with SlipGate.
- If you run your own server: never hand out `root` or any shell-login account as a VPN credential — always create dedicated SlipGate users.

Channel: [@SlipNet_app](https://t.me/SlipNet_app)
Source: https://github.com/anonvector/SlipNet

---
---

# راهنمای کامل SlipNet (فارسی)

> کانال رسمی: [@SlipNet_app](https://t.me/SlipNet_app)
> سورس‌کد: https://github.com/anonvector/SlipNet
> SlipNet در گوگل‌پلی، اپ‌استور یا هیچ مارکت دیگری نیست. فقط از کانال رسمی یا گیت‌هاب دانلود کنید.

---

## فهرست

- ۱. SlipNet چیست و چرا ساخته شده
- ۲. تونل‌های پشتیبانی‌شده
- ۳. نسخه‌ها: Full و Lite
- ۴. نصب APK
- ۵. سرور لازم است (با SlipGate)
- ۶. اولین پروفایل
- ۷. اتصال و قطع
- ۸. اسکنر DNS
- ۹. زنجیره‌ی پروفایل (Chains)
- ۱۰. مرجع تنظیمات
- ۱۱. مرجع سریع هر تونل
- ۱۲. عیب‌یابی
- ۱۳. اشتراک‌گذاری و پشتیبان
- ۱۴. حمایت مالی
- ۱۵. نکات امنیتی

---

## ۱. SlipNet چیست و چرا ساخته شده

SlipNet یک ابزار رایگان و **source-available** (سورس‌کدش قابل مطالعه است، اما اجازه‌ی توزیع مجدد ندارد) برای دور زدن سانسور و بازرسی شبکه است. نسخه‌ی اصلی برای اندروید است و یک کلاینت CLI هم برای مک، لینوکس و ویندوز ارائه می‌شود. SlipNet ترافیک اینترنت شما را از داخل پروتکل‌های متفاوتی مثل DNS، QUIC، SSH، HTTPS، VLESS یا Tor عبور می‌دهد تا حتی در شبکه‌هایی که اینترنت در آن‌ها فیلتر، محدود یا با DPI بازرسی می‌شود، بتوانید آزادانه به وب دسترسی پیدا کنید.

برخلاف یک VPN معمولی که تنها یک پروتکل دارد، SlipNet چند **حامل (transport)** مختلف ارائه می‌کند تا متناسب با شرایط شبکه‌ای که در آن گیر افتاده‌اید بتوانید بهترین مسیر را انتخاب کنید:

- اگر ISP فقط ترافیک DNS را عبور می‌دهد، از تونل‌های DNS مثل DNSTT، NoizDNS یا VayDNS استفاده کنید.
- اگر فقط HTTPS کار می‌کند، می‌توانید به سراغ NaiveProxy یا VLESS از پشت CDN (مثل Cloudflare) بروید.
- اگر شبکه به‌شدت بازرسی می‌شود و الگوی ترافیک شما را تشخیص می‌دهد، می‌توانید روی هر کدام از این تونل‌ها یک لایه‌ی SSH هم اضافه کنید تا نشت DNS صفر شود و ترافیک رمزنگاری بیشتری داشته باشد.
- در سخت‌ترین شرایط، می‌توانید از Tor همراه با Snowflake، obfs4 یا Meek استفاده کنید (فقط در نسخه‌ی Full).

از نظر فلسفه، SlipNet در همان خانواده‌ی پروژه‌های ضد سانسور قرار می‌گیرد که [Tor](https://torproject.org)، [Psiphon](https://psiphon.ca) و [Outline VPN](https://getoutline.org) متعلق به آن هستند؛ با این تفاوت مهم که SlipNet **فقط کلاینت** است: شبکه یا سرور مرکزی متعلق به یک سازمان خاص وجود ندارد و سرور را یا خودتان راه‌اندازی می‌کنید (با [SlipGate](https://github.com/anonvector/slipgate) فقط چند دقیقه طول می‌کشد) یا از طریق فردی مورد اعتماد دریافت می‌کنید. این مدل سه مزیت اصلی دارد:

- **حریم خصوصی**: ترافیک شما از سروری عبور می‌کند که خودتان یا کسی که می‌شناسید کنترل می‌کند، نه یک شرکت ناشناس.
- **مقیاس‌پذیری و دوام**: چون هیچ زیرساخت متمرکزی برای فیلتر کردن وجود ندارد، حتی اگر یک سرور بلاک شود، یک IP جدید و تغییر یک رکورد DNS کافی است.
- **انعطاف**: می‌توانید پروتکل، CDN، دامنه و حتی کشور سرور را خودتان انتخاب کنید — چیزی که هیچ VPN تجاری به شما نمی‌دهد.

سورس‌کد SlipNet به‌صورت کامل روی گیت‌هاب در دسترس است (تحت لایسنس source-available — قابل مطالعه و مشارکت، اما بدون اجازه‌ی توزیع مجدد یا انتشار در استورها) و در هیچ مارکت اپ (گوگل‌پلی، اپ‌استور و…) منتشر نمی‌شود؛ تنها منبع رسمی، کانال [@SlipNet_app](https://t.me/SlipNet_app) و مخزن گیت‌هاب پروژه است.

---

## ۲. تونل‌های پشتیبانی‌شده

| تونل | پروتکل | کارش | برای چه شبکه‌ای |
|------|---------|------|---------------|
| **DNSTT** | DNS (KCP + Noise) | ترافیک را در کوئری DNS می‌فرستد | شبکه‌هایی که فقط DNS باز است |
| **NoizDNS** | DNS (KCP + Noise) | DNSTT با مقاومت در برابر DPI (انکودینگ base36/hex، حذف پیشوند CDN) | شبکه‌های تحت بازرسی شدید |
| **VayDNS** | DNS (KCP + Curve25519) | تونل DNS بهینه و قابل تنظیم | کاربران حرفه‌ای |
| **Slipstream** | QUIC | تونل پرسرعت QUIC | شبکه‌های سالم |
| **SSH** | SSH | تونل SSH ساده و رمزنگاری‌شده | امنیت ساده، بدون نشت |
| **NaiveProxy** | HTTPS (Caddy + اثرانگشت TLS کروم) | HTTPS با اثرانگشت اصیل کروم | عبور از DPI روی HTTPS |
| **VLESS** | WebSocket (روی TLS یا plain) | VLESS روی WebSocket پشت CDN (مثل Cloudflare) | فرانتینگ CDN، بسیار رایج در ایران |
| **DOH** | DNS over HTTPS | فقط DNS را رمزنگاری می‌کند | عبور از فیلترینگ DNS |
| **Tor** | Tor + Snowflake/obfs4/Meek | شبکه‌ی ناشناس | ناشناسی بالا |
| **+ نسخه‌های SSH** | (DNSTT/NoizDNS/VayDNS/Slipstream/NaiveProxy/VLESS) + SSH | یک لایه‌ی SSH اضافه — نشت DNS صفر | حداکثر امنیت |

**کدام را انتخاب کنم؟**

- تازه‌کار و گیج؟ → **DNSTT** (پیش‌فرض).
- DPI سخت؟ → **NoizDNS** یا **NoizDNS + SSH**.
- می‌خوای پشت CloudFlare قایم شی؟ → **VLESS** یا **NaiveProxy**.
- سرعت خام روی شبکه‌ی تمیز؟ → **Slipstream**.
- ناشناسی؟ → **Tor** (فقط نسخه Full).

---

## ۳. نسخه‌ها: Full و Lite

SlipNet در دو نسخه عرضه می‌شود — تفاوت در حجم APK و پروتکل‌های موجود است.

| ویژگی | Full | Lite |
|-------|:----:|:----:|
| DNSTT، NoizDNS، VayDNS | ✓ | ✓ |
| Slipstream (QUIC) | ✓ | ✓ |
| SSH | ✓ | ✓ |
| DoH | ✓ | ✓ |
| VLESS | ✓ | ✓ |
| **NaiveProxy** | ✓ | — |
| **Tor (Snowflake / obfs4 / Meek)** | ✓ | — |
| حجم تقریبی APK | حدود ۵۰ MB | حدود ۲۰ MB |

پیشنهاد پیش‌فرض **Full** است. **Lite** برای اینترنت کند، گوشی با حافظه‌ی کم، یا وقتی Tor و NaiveProxy لازم نیست.

---

## ۴. نصب APK

۱. کانال رسمی [@SlipNet_app](https://t.me/SlipNet_app) یا صفحه‌ی Releases در گیت‌هاب را باز کنید.
۲. APK مناسب CPU گوشی‌تان را دانلود کنید. اکثر گوشی‌های جدید `arm64-v8a` هستند. اگر مطمئن نیستید، APK نسخه‌ی **universal** را بگیرید.
۳. در گوشی: **تنظیمات → امنیت → نصب از منابع ناشناس** را برای مرورگر یا تلگرام فعال کنید.
۴. روی APK دانلودشده بزنید و نصب کنید.
۵. اپ را باز کنید. در اولین اجرا، اندروید مجوز VPN می‌خواهد — **OK** را بزنید.
۶. تنظیم پیشنهادی یک‌باره: **تنظیمات → بهینه‌سازی باتری → SlipNet را بهینه نکن** تا اندروید آن را در پس‌زمینه نکشد.

> ⚠️ اگر SlipNet را در گوگل‌پلی، اپ‌استور یا هر مارکت دیگری دیدید، **مال ما نیست**؛ نصب نکنید.

---

## ۵. سرور لازم است — از SlipGate استفاده کنید

SlipNet *کلاینت* است. برای کار به یک **سرور** نیاز دارد که تونل سازگار را اجرا کند.

روش رسمی و پشتیبانی‌شده برای راه‌اندازی سرور **SlipGate** است — یک نصاب لینوکسی تک‌دستوری که سمت سرور تمام پروتکل‌های SlipNet را راه می‌اندازد.

> https://github.com/anonvector/slipgate

راهنمای جداگانه‌ی SlipGate در کنار همین سند منتشر شده است. خلاصه: یک VPS ۵ دلاری بگیرید، دامنه‌اش را به آن وصل کنید، یک دستور نصب اجرا کنید، یک کاربر بسازید، و SlipGate یک لینک `slipnet://` می‌دهد که مستقیم در اپ پیست می‌شود.

اگر سرور خودتان را راه نمی‌اندازید، می‌توانید:
- از دوستی که SlipGate دارد لینک `slipnet://` بگیرید، یا
- از لینک تستی عمومی که گاهی در [@SlipNet_app](https://t.me/SlipNet_app) منتشر می‌شود استفاده کنید.

---

## ۶. اولین پروفایل

سه راه برای ساخت پروفایل وجود دارد.

### الف) چسباندن لینک `slipnet://` (ساده‌ترین)

۱. SlipNet را باز کنید → دکمه‌ی **+** پایین سمت راست.
۲. **Import from URI** را انتخاب کنید.
۳. لینک `slipnet://...` را پیست کنید.
۴. تمام — پروفایل به لیست اضافه می‌شود.

### ب) ایمپورت فایل JSON

اگر دوستی پروفایل‌هایش را خروجی گرفته (رمزشده یا ساده):

۱. منوی سه‌نقطه (⋮) صفحه‌ی اصلی → **Import Profiles**.
۲. فایل `.json` را انتخاب کنید.
۳. اگر رمزشده است، رمز را وارد کنید.

### پ) ساخت دستی پروفایل

وقتی به‌جای URI، مقادیر خام (دامنه + کلید) داده شده.

۱. روی **+** بزنید → **Add Profile**.
۲. یک **Name** بگذارید.
۳. **Tunnel Type** را انتخاب کنید (بسته به نوع، فیلدها فرق می‌کند — به بخش ۱۱ نگاه کنید).
۴. فیلدهای موردنیاز را پر کنید.
۵. **Save** بزنید.

---

## ۷. اتصال و قطع

۱. روی پروفایل دلخواه در لیست بزنید (یک تیک می‌آید).
۲. دکمه‌ی بزرگ **Connect** را بزنید.
۳. اولین بار اندروید مجوز VPN می‌خواهد → **OK**.
۴. وقتی آیکن سبز شد و آمار آپلود/دانلود زنده دیده شد، متصل هستید. تمام ترافیک از تونل عبور می‌کند.

برای قطع، دوباره **Connect** را بزنید. برای تعویض پروفایل، اول قطع کنید، پروفایل دیگر را انتخاب و دوباره وصل کنید.

**سوییچ سریع بدون باز کردن اپ:**
- نوار اعلان را پایین بکشید → **کاشی Quick Settings** SlipNet را بزنید (اولین بار باید از پنل کاشی‌ها اضافه‌اش کنید).
- یا از **ویجت صفحه‌ی اصلی** برای اتصال یک‌ضربه‌ای استفاده کنید.

**تست پینگ زنده:** پس از انتخاب پروفایل، روی **Real Ping** یا **Simple Ping** بزنید. **Sort by Ping** لیست را از سریع‌ترین مرتب می‌کند.

---

## ۸. اسکنر DNS

پروفایل‌های تونل DNS (DNSTT، NoizDNS، VayDNS) فقط از طریق ریزالورهایی کار می‌کنند که چند رفتار RFCای را رعایت کنند و در پاسخ‌ها دست‌کاری نکنند. خیلی از ریزالورهای ISPها در یک یا چند مورد از این تست‌ها مردود می‌شوند — NXDOMAIN را hijack می‌کنند، EDNS را حذف می‌کنند، نام‌های طولانی را رد می‌کنند، یا ترافیک شبیه‌تونل را در DPI می‌بندند. **اسکنر** ریزالورهایی را پیدا می‌کند که از این تست‌ها رد می‌شوند.

باز کردن: **منو → DNS Resolver Scanner**.

اسکنر چهار چیز اصلی را در اختیار شما می‌گذارد:

۱. **حالت اسکن (Scan Mode)** — چه نوع تستی اجرا شود
۲. **پنل پیکربندی (Configuration)** — دامنه تست، پورت، تایم‌اوت، موازی‌سازی
۳. **منبع IP (IP source)** — IPهای کاندید از کجا بیایند
۴. **نتایج و اعمال (Results & Apply)** — مرور و push کردن به پروفایل

---

### ۸.۱. حالت‌های اسکن

یک تاگل بالای صفحه یکی از چهار حالت را انتخاب می‌کند. هر کدام trade-off متفاوتی بین سرعت، عمق و قطعیت دارد.

#### Simple
*«ریزالورهای DNS را اسکن می‌کند و خودکار هر کدام را از تونل تست می‌کند. فقط ریزالورهایی که از تست تونل رد می‌شوند نمایش داده می‌شوند.»*

حالت یک‌ضربه‌ای برای همه. اسکنر هم پروب سازگاری DNS و هم تست end-to-end تونل را در یک pipeline اجرا می‌کند و فقط ریزالورهایی را نشان می‌دهد که واقعاً ترافیک را می‌رسانند. اگر نمی‌خواهید فکر کنید، این را انتخاب کنید.

نیاز به پروفایلی با کلید عمومی معتبر دارد (تا تست تونل سرور واقعی برای حرف زدن داشته باشد).

#### Advanced
*«اول ریزالورها را اسکن کن، بعد در صورت نیاز تست تونل را جدا اجرا کن.»*

جریان دو-مرحله‌ای کلاسیک. مرحله ۱ پروب DNS است و به هر ریزالور امتیاز ۰ تا ۶ می‌دهد (به ۸.۵ نگاه کنید). می‌توانید نتایج را مرور، مرتب و فیلتر کنید، و بعد در صورت نیاز یک تست تونل E2E روی ریزالورهای رد شده اجرا کنید. وقتی می‌خواهید جزئیات پروب را ببینید یا هنوز پروفایل ندارید، این مفید است.

#### E2E
*«هر ریزالور را مستقیم از تونل تست می‌کند، بدون چک سازگاری DNS. کندتر است ولی اتصال واقعی را تست می‌کند.»*

پروب DNS را کامل رد می‌کند. برای هر IP کاندید فقط یک تونل واقعی باز می‌کند و یک درخواست HTTP می‌فرستد. وقتی از قبل لیست IPهای «شناخته‌شده‌ی تونل-سازگار» دارید و فقط می‌خواهید بدانید کدام در حال حاضر سریع به سرور خاص شما می‌رسد، این را انتخاب کنید.

#### Prism
*«اسکن سرور-تأییدشده: فقط ریزالورهایی نمایش داده می‌شوند که به‌صورت رمزنگاری‌شده اثبات کنند به سرور خاص شما می‌رسند. به نصب SlipGate روی سرور نیاز دارد.»*

قوی‌ترین حالت. پروب‌های HMAC-authenticated می‌فرستد که فقط یک سرور SlipGate واقعی می‌تواند درست امضا کند، پس ریزالوری که «کار می‌کند» اما در واقع ترافیک را به یک middlebox مهاجم می‌رساند، در این چک رد می‌شود. هر ریزالور N بار پروب می‌شود؛ ریزالورهایی که ≥ *threshold* پاسخ امضاشده می‌گیرند، عبور می‌کنند. وقتی به transparent-proxy interception شک دارید یا می‌خواهید جلوی hijacking تونل را بگیرید، این را انتخاب کنید.

فقط وقتی پروفایل انتخاب‌شده‌تان کلید عمومی معتبر دارد و سرور شما [SlipGate](https://github.com/anonvector/slipgate) اجرا می‌کند، در دسترس است.

---

### ۸.۲. پنل پیکربندی

این فیلدها بالای دکمه‌ی اسکن می‌آیند. اکثرشان مقدار پیش‌فرض درستی دارند — فقط وقتی اسکن نتیجه نمی‌دهد دستکاری کنید.

**مشترک Simple / Advanced**
- **Test Domain** — اسمی که پروب می‌پرسد. *دامنه‌ی تونل خودتان* را بگذارید (مثل `t.example.com`)؛ ریزالوری که می‌تواند زیردامنه‌های تصادفی طولانی زیر آن را روت کند، همان است که می‌تواند تونل واقعی را حمل کند. در پروفایل‌های قفل‌شده به دامنه‌ی خود پروفایل برمی‌گردد.
- **Port** — معمولاً `53`. اگر سرورتان روی پورت غیراستاندارد است، عوض کنید.
- **Timeout (ms)** — تایم‌اوت پروب DNS برای هر ریزالور. پیش‌فرض ۳۰۰۰. اگر لیست کاندیدتان عظیم و پر از IP مرده است، روی ۱۵۰۰ بگذارید.
- **Workers** — تعداد پروب موازی. پیش‌فرض ۵۰. روی شبکه‌ی ناپایدار کم کنید تا drops نداشته باشید.

**فقط E2E**
- **Resolver Port** — پورتی که ریزالور گوش می‌دهد (۵۳ مگر تغییر داده باشید).
- **E2E Timeout** — تایم‌اوت تست تونل هر ریزالور. پیش‌فرض ۱۵۰۰۰ ms.
- **E2E Concurrency** — تعداد تست تونل موازی. ۱ تا ۱۰. **Slipstream حداکثر ۱** چون تونل‌های QUIC نمی‌توانند پورت را به اشتراک بگذارند.
- **Test URL** — چیزی که تونل برای اثبات اتصال می‌گیرد. پیش‌فرض `http://www.gstatic.com/generate_204` (پاسخ 204 No Content — کوچک، سریع، به DNS داخل تونل وابسته نیست).
- **Full Verification** — وقتی روشن است، URL تست را از تونل زنده می‌گیرد؛ وقتی خاموش، فقط تأیید می‌کند که handshake تونل کامل شد.

**فقط Prism**
- **Probes** — تعداد درخواست‌های HMAC-signed به هر ریزالور. پروب بیشتر = اطمینان آماری قوی‌تر، اسکن کندتر. پیش‌فرض ۵.
- **Pass threshold** — حداقل تعداد پروبی که باید درست امضاشده برگردد. پیش‌فرض ۲.
- **Timeout (per resolver)** — بودجه‌ی کلی که بین پروب‌ها تقسیم می‌شود. اپ تنظیماتی را که زمان هر پروب زیر ۲۰۰ ms می‌شود رد می‌کند.
- **Response size** — بایتی که سرور باید پاسخ‌ها را تا آن پد کند (0 = پیش‌فرض سرور). اگر سرورتان برای اندازه‌ی پاسخ خاصی پیکربندی شده، مفید است.
- **Pre-filter dead resolvers** — اول یک چک سریع DNS اجرا می‌کند تا IPهای مرده را قبل از مصرف بودجه پروب حذف کند. برای لیست‌های بزرگ پیشنهاد می‌شود.

**Scan Transport (فقط Advanced و Simple)** — `UDP`، `TCP` یا `Both`. **Both** اول UDP اجرا می‌کند، بعد فقط ریزالورهایی که نگذشتند را روی TCP دوباره تست می‌کند. در شبکه‌هایی که UDP DNS rate-limit یا فیلتر می‌شود مفید است، چون بعضی ریزالورها روی TCP خوب پاسخ می‌دهند. هر نتیجه نشان `UDP` و `TCP` نشان می‌دهد که از کدام عبور کرده.

---

### ۸.۳. پنل منبع IP

تب‌های پایین تعیین می‌کنند *IPهای کاندید از کجا بیایند*. هر بار فقط یک منبع.

- **Default** — لیست ازپیش‌منتخب اپ از ریزالورهایی که در گذشته جواب می‌دادند. کوچک‌ترین و سریع‌ترین اسکن؛ شروع خوب.
- **Import** — IP از فایل بارگذاری کن (`.txt`، یکی در خط یا با کاما). برای اسکن لیست دیگران یا نتایج خودتان مفید است.
- **Country** — IP تصادفی از تخصیص آدرس یک کشور تولید می‌کند. کشور و sample count را انتخاب کنید (پیش‌فرض ۲۰۰۰، حداکثر ۱۰۰٬۰۰۰). برای کاربران ایران معمولاً معدن طلاست — ریزالورهای داخلی معمولاً برای تونل بهتر از خارجی‌ها هستند، چون DPI داخلی به اندازه‌ی کافی روی آن‌ها حساسیت ندارد.
- **Custom** — یک CIDR (`5.144.0.0/14`)، یک رنج (`5.144.0.1-5.147.255.254`)، IPهای کاما-جداشده یا تک IP پیست کنید. پیش‌نمایش شمارش نشان می‌دهد چند IP در صف اسکن قرار می‌گیرد.
- **IR DNS Ranges** — تخصیص DNS ایرانی گروه‌بندی‌شده با `/8` اول. انتخاب کنید کدام گروه‌ها باشند (نشان شماره روی هر گروه تعداد IP کل آن را می‌گوید). سنگین‌تر از IR DNS Lite ولی جامع‌تر.
- **IR DNS Lite** — زیرمجموعه‌ی ازپیش‌منتخب از رنج‌های DNS ایرانی، کوچک‌تر و سریع‌تر از کامل. پیش‌فرض خوبی برای کاربران ایران.
- **Recent DNS** *(دکمه‌ی پایین)* — IPهای آخرین اسکن را دوباره استفاده می‌کند، برای تنظیم پارامترها بدون تولید مجدد لیست کاندید.
- **Load Last Scan IPs** — ریزالورهایی را که در اجرای قبلی قبلاً قبول شده‌اند برمی‌گرداند («Working IPs» را از «E2E Passed IPs» جدا نگه می‌دارد تا فقط لیست اثبات‌شده را دوباره تست کنید).

تاگل‌هایی که برای اکثر منابع کار می‌کنند:
- **Shuffle** — ترتیب اسکن را تصادفی کن. پیش‌فرض روشن. کمک می‌کند روی یک ISP خاص متمرکز نشوید.
- **Expand neighbours** — موقع اسکن یک رنج سفارشی، چند IP اطراف هر hit را هم پروب کن، چون ریزالورها معمولاً خوشه‌خوشه هستند.

---

### ۸.۴. نتایج و اعمال

پس از اتمام اسکن، **View Results** را بزنید. هر سطر ریزالور این‌ها را نشان می‌دهد:

- IP ریزالور و امتیاز (۰ تا ۶) از پروب DNS.
- یک نشان تفکیکی: `NS✓ TXT✓ RND✓ DPI✓ EDNS✓(1232) NXD✓` — به ۸.۵ نگاه کنید.
- در حالت Simple/E2E: زمان setup تونل، تأخیر HTTP، کل round-trip.
- در حالت Prism: `Probes 4/5` (موفق/کل) و نشان `Verified`.
- نشان transport (`UDP`، `TCP`) که از کدام رد شده.
- وضعیت `WORKING` / `CENSORED` / `TIMEOUT` / `ERROR`.

می‌توانید:
- **مرتب** کن بر اساس امتیاز، تأخیر یا موفقیت E2E.
- **فیلتر** بر اساس تعداد پروب رد شده (Prism)، رنج امتیاز (Advanced)، یا «همه‌ی working».
- **سرچ** بر اساس بخشی از IP.
- **کپی** یا **خروجی** IPهای دیده‌شده (فقط E2E-passed / فقط Stage-1 working / انتخاب خودتان).
- **Re-test Tunnel** روی یک نتیجه — وقتی شبکه عوض شده مفید است.
- **Apply Selected** — ریزالورهای انتخاب‌شده را روی پروفایل فعال اعمال می‌کند (حداکثر ۸). دفعه‌ی بعد که وصل می‌شوید، همان ریزالورها استفاده می‌شوند.

اسکن قطع‌شده را می‌توانید resume کنید (اپ هنگام ورود مجدد می‌پرسد). تست‌های E2E را می‌توانید وسط اجرا pause/continue کنید.

---

### ۸.۵. شرح امتیاز ۰ تا ۶

امتیاز سازگاری DNS برابر است با تعداد تست‌هایی از این شش پروب که ریزالور با موفقیت پشت سر می‌گذارد. هر پروب یک امتیاز دارد (موفق یا ناموفق).

| پروب | چه چیزی را می‌سنجد | چرا مهم است |
|------|--------------------|--------------|
| **NS** | آیا ریزالور رکورد `NS` را دنبال می‌کند و رکورد A زون والد را برمی‌گرداند | سرور تونل معمولاً به‌صورت زیردامنه به سرور شما واگذار (delegate) می‌شود؛ ریزالوری که از این واگذاری پیروی نکند، اصلاً نمی‌تواند سرور تونل را پیدا کند |
| **TXT** | آیا ریزالور رکوردهای TXT را به‌درستی برمی‌گرداند | DNSTT، NoizDNS و VayDNS داده‌ی بازگشتی را داخل رکوردهای TXT (یا انواع دیگر در تنظیمات VayDNS) رمزگذاری می‌کنند؛ اگر TXT کار نکند، هیچ ترافیکی از سرور به کلاینت نمی‌رسد |
| **RND** | آیا ریزالور برای زیردامنه‌ای که قبلاً ندیده، واقعاً از سرور بالادست (upstream) سؤال می‌کند | برخی ریزالورها بیش از حد کش می‌کنند یا نام‌های ناشناس را بدون پرسش رد می‌کنند؛ تونل DNS برای هر درخواست یک زیردامنه‌ی جدید می‌سازد، پس این رفتار باید درست باشد |
| **DPI** | آیا یک کوئری TXT طولانی base32 به سبک `dnstt` از فیلترینگ DPI عبور می‌کند | برخی شبکه‌ها با شناسایی الگوی DNS-tunnel (طول، آنتروپی یا نوع رکورد) آن را می‌بندند؛ اگر این تست رد شود، کوئری‌ها بی‌سر و صدا حذف می‌شوند |
| **EDNS** | آیا ریزالور پاسخ‌های EDNS0 بزرگ‌تر از ۵۱۲ بایت را پشتیبانی می‌کند (و حداکثر اندازه‌ی payload — مثلاً ۵۱۲ یا ۹۰۰ یا ۱۲۳۲) | سرعت تونل مستقیماً به اندازه‌ی پاسخ بستگی دارد؛ ۱۲۳۲ مقدار توصیه‌شده‌ی dnsflagday.net است و ریزالورهایی که روی ۵۱۲ گیر کرده‌اند بسیار کند خواهند بود |
| **NXD** | آیا ریزالور برای دامنه‌ی نامعتبر، پاسخ صحیح `NXDOMAIN` می‌دهد یا آن را به یک IP جعلی هدایت می‌کند | ریزالورهایی که NXDOMAIN را hijack می‌کنند پاسخ ساختگی می‌فرستند و این کار قاب‌بندی تونل را خراب می‌کند؛ چنین ریزالوری امتیاز `NXD✗` می‌گیرد و عملاً غیرقابل‌استفاده است |

امتیاز **۶** یعنی ریزالور کاملاً با تونل سازگار است. امتیاز **۵** معمولاً قابل قبول است — اغلب تنها امتیاز ازدست‌رفته مربوط به اندازه‌ی payload EDNS است که فقط روی سرعت اثر می‌گذارد. امتیاز **۳ یا کمتر** معمولاً ارزش استفاده ندارد. با فیلد Pass threshold می‌توانید حداقل امتیاز قابل قبول را تعیین کنید.

---

### ۸.۶. دستورهای کاربردی

- **کاربر ایران، پروفایل پیش‌فرض، فقط می‌خواهی وصل شی**: حالت Simple → منبع IR DNS Lite → Start.
- **کاربر ایران، جستجوی همه‌جانبه**: حالت Simple → منبع IR DNS Ranges → همه‌ی گروه‌ها را انتخاب کن → sample count را روی ۵۰۰۰ ببر.
- **تست‌کننده‌ی خارجی**: حالت Advanced → منبع Country → کشور را انتخاب کن → score threshold روی ۵.
- **شک داری ISP intercept می‌کند**: حالت Prism → IR DNS Lite → ۸ probe / threshold ۵.
- **لیست کارا داری، فقط سرعت را تأیید کن**: حالت E2E → آن لیست را Import کن → concurrency بالا.
- **UDP DNS rate-limit شده**: هر حالتی → Scan Transport را روی `Both` بگذار.

---

## ۹. زنجیره‌ی پروفایل (Chains)

تب **Chains** اجازه می‌دهد چند پروفایل را پشت سر هم بگذارید. مثال‌ها:

- `NoizDNS → SSH → مقصد` — حمل‌کننده‌ی مقاوم در برابر DPI با SSH روی آن، نشت DNS صفر.
- `VLESS (Cloudflare) → SSH` — فرانتینگ CDN به‌علاوه آخرین‌گام رمزنگاری‌شده.
- `Tor → NaiveProxy` — ناشناسی + خروجی HTTPS.

**ساخت زنجیره:**
۱. تب **Chains** را باز کنید.
۲. **+ New Chain** را بزنید.
۳. پروفایل‌ها را به ترتیب اضافه کنید — اولین گام بالا، آخرین گام پایین.
۴. ذخیره و انتخاب مثل یک پروفایل عادی.

موقع اتصال، اپ سازگاری زنجیره را اعتبارسنجی می‌کند (transportهای سازگار، بدون حلقه) و زنجیره را به‌عنوان یک تونل اجرا می‌کند.

---

## ۱۰. مرجع تنظیمات

با باز کردن **Settings**:

**Connection**
- **Auto-connect on boot** — با روشن شدن گوشی خودکار وصل شو.
- **Auto-reconnect** — اگر VPN قطع شد دوباره وصل شو.
- **Auto-disconnect after** — بعد از مدت بی‌مصرفی قطع شو.
- **Block all if VPN drops** — کلید قطع اضطراری (بدون نشت).
- **VPN MTU** — کم کن (مثلاً 1280) اگر بعضی سایت‌ها لود نمی‌شوند.
- **DNS Workers** — کمتر = پایدارتر روی شبکه‌های محدود؛ "per-query" برای هر لوک‌آپ یک کانکشن جدید.
- **Disable QUIC** — اپ‌ها را به TCP مجبور می‌کند؛ معمولاً روی تونل سریع‌تر است.

**Routing**
- **Split Tunneling** — انتخاب اپ‌هایی که از VPN رد می‌شوند (allow / bypass).
- **Domain Routing** — فقط دامنه‌های خاصی از تونل عبور کنند.
- **Geo-bypass** — ترافیک مربوط به IPها/سایت‌های کشور انتخاب‌شده را *بیرون* از تونل می‌فرستد تا سایت‌های داخلی سریع و بدون اثر تونل بمانند.
- **Bypass VPN** — اپ‌هایی که VPN را دور بزنند.
- **Append HTTP Proxy to VPN** — یک پراکسی HTTP محلی هم می‌سازد.

**DNS**
- **Global DNS Resolvers** — جایگزینی ریزالورها برای همه‌ی پروفایل‌ها.
- **Remote DNS Server** — DNS سمت سرور تونل.
- **DNS Resolver Scanner** — به بخش ۸ نگاه کنید.

**Security**
- **SSH Cipher** — AES-128-GCM / ChaCha20 / AES-128-CTR (legacy).
- **Bandwidth Limit** — سقف آپلود/دانلود.
- **Hotspot mode** — تونل را با دستگاه‌های دیگر روی Wi-Fi به اشتراک بگذار.

**Appearance**
- **Dark mode** — Dark / AMOLED Dark / Auto.

**Diagnostics**
- **Debug logging** — لاگ پرجزئیات برای پشتیبانی.
- **Device ID / IP** — برای درخواست پشتیبانی کپی کنید.
- **Check for updates** — آخرین نسخه را می‌گیرد.

---

## ۱۱. مرجع سریع هر تونل

وقتی پروفایل را به‌صورت دستی می‌سازید، هر نوع تونل به این فیلدها نیاز دارد:

### DNSTT / NoizDNS
- **Domain** — زیردامنه‌ی تونل، مثل `t.example.com`
- **Public Key** — کلید Curve25519/Noise سرور (هگز)
- **DNS Transport** — UDP / TCP / DoT / DoH
- **DNS Resolvers** — IPهای ریزالورها
- *NoizDNS:* **Stealth Mode** — کندتر اما سخت‌تر برای تشخیص

### VayDNS
- Domain + Public Key (مثل بالا)
- **Record Type** — TXT / CNAME / A / AAAA / MX / NS / SRV
- **Max QNAME Length** — حجم سیمی هر کوئری
- **Rate Limit (RPS)** — تعداد کوئری در ثانیه
- **Idle Timeout / Keep-Alive / UDP Timeout**
- **ClientID Size** — باید با سرور یکی باشد (پیش‌فرض ۲؛ در حالت DNSTT-compat برابر ۸)

### Slipstream
- Domain + Public Key
- **Congestion Control** — BBR / DCUBIC
- **Keep-Alive Interval**
- **Authoritative Mode**, **GSO**

### SSH (مستقل یا به‌عنوان آخرین گام)
- **SSH Host / Port** (پیش‌فرض ۲۲)
- **Username + Password** *یا* **Private Key** (با passphrase)
- **Cipher** — AES-128-GCM / ChaCha20 / AES-128-CTR

گزینه‌های transport برای SSH (روی هر تونل SSH-base کار می‌کند):
- **SSH over TLS** — SSH را در TLS با SNI سفارشی بپوشاند (domain fronting).
- **HTTP CONNECT proxy** — مسیر از پراکسی HTTP CONNECT با Host سفارشی.
- **SSH over WebSocket** — `ws://` یا `wss://` با path و Host سفارشی (سازگار با Cloudflare).
- **SSH Payload** — قبل از handshake بایت خام بفرست تا کانکشن استتار شود. placeholder: `[host]`، `[port]`، `[crlf]`، `[cr]`، `[lf]`.

### NaiveProxy
- **Server hostname** + **port** (معمولاً ۴۴۳)
- **Proxy username / password**

### VLESS
- **UUID** — شناسه‌ی کاربر VLESS (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
- **Domain** — هاست پشت CDN؛ به‌عنوان TLS SNI و WS Host
- **Security** — `tls` (پیشنهادی) یا `none`
- **Transport** — فقط WebSocket (TCP خام در اپ پشتیبانی نمی‌شود — VLESS در SlipNet به‌عنوان تونل پشت CDN در نظر گرفته شده)
- **WS Path** — مثلاً `/`، `/vless`
- **CDN IP / Port** — یک IP تمیز Cloudflare اگر فرانتینگ CF می‌کنید (وگرنه IP مستقیم سرور، پورت ۴۴۳)
- **TLS SNI** — چیزی که در ClientHello می‌رود (موقع روتینگ روی CDN باید با گواهی CDN بخواند)
- **SNI Fragmentation** — DPI-evasion سمت TLS: split / pad کردن ClientHello (اگر ISP شما VLESS را تشخیص می‌دهد، روشنش کنید)
- **Header obfuscation** *(فقط WS)* — هدرهای تصادفی مرورگری

### SOCKS5 (زنجیر کردن به یک پراکسی SOCKS5 ریموت)
- **Host / Port** پراکسی SOCKS5 ریموت
- **Username / Password** (اختیاری، RFC 1929)
- **DNS Server** برای DNS-over-TCP داخل تونل (پیش‌فرض `8.8.8.8`)

#### ⚠️ چرا SOCKS5 ممکن است «Connected» نشان دهد ولی واقعاً کار نکند

حالت SOCKS5 در SlipNet یک **passthrough** ساده است — فقط یک listener محلی روی گوشی باز می‌کند و هر درخواست را به پراکسی SOCKS5 ریموت زنجیر می‌کند. **هیچ تست end-to-end اولیه‌ای انجام نمی‌شود.** وضعیت «Connected» فقط دو چیز را تأیید می‌کند:

1. listener محلی SOCKS5 روی گوشی شما با موفقیت bind شده، و
2. یک کانکشن downstream توانسته handshake (CONNECT + auth) را با پراکسی ریموت کامل کند.

این **تأیید نمی‌کند** که پراکسی ریموت واقعاً به اینترنت آزاد دسترسی دارد. پراکسی می‌تواند بی‌سروصدا ترافیک خروجی را drop کند، پاسخ CONNECT جعلی برگرداند، پشت یک فایروال ابری باشد که فقط CIDR داخلی را اجازه می‌دهد، یا خودش پشت uplink سانسورشده گیر کرده باشد — و SlipNet هیچ راهی برای تشخیص این‌ها از روی پروتکل SOCKS5 ندارد، چون SOCKS5 **نه هویت سرور را تأیید می‌کند، نه key exchange سرتاسری دارد، نه سیگنال liveness**.

#### مقایسه‌ی SSH و SOCKS5

برقراری تونل SSH شامل این مراحل است که همه باید موفق شوند تا instance خودش را connected اعلام کند:

- TCP connect به endpoint سرور SSH
- تبادل بنر نسخه‌ی SSH
- Key Exchange (ECDH/DH) و تولید کلید نشست مشترک
- احراز هویت کاربر (password یا public-key) — توسط سرور اعتبارسنجی می‌شود
- باز شدن یک channel واقعی روی نشست رمزنگاری‌شده

اگر هر کدام از این مراحل fail شود، SSH هرگز به وضعیت سبز نمی‌رسد. بنابراین وقتی SSH می‌گوید «connected»، یعنی واقعاً یک کانال رمزنگاری‌شده و احراز هویت‌شده وجود دارد و در حال انتقال بایت است. به همین خاطر **تونل‌های مبتنی بر SSH وقتی چیزی خراب باشد صدای بلندی در می‌آورند**، در حالی که SOCKS5 ساده می‌تواند یک وضعیت سبزِ دروغی نشان دهد.

| | SOCKS5 | SSH |
|---|---|---|
| تأیید هویت سرور | ندارد | ضمنی از طریق احراز هویت (و host-key اگر pin شده باشد) |
| Key exchange سرتاسری | ندارد | بله (ECDH/DH) |
| «Connected» یعنی ترافیک رد می‌شود | خیر | بله |
| رمزنگاری تا سرور | خیر (متن ساده تا پراکسی) | بله |
| تشخیص MITM / drop خاموش | ندارد | دارد |

> **همین مشکل روی تونل‌های DNS هم می‌تواند رخ دهد.** DNSTT، NoizDNS و VayDNS در حالت **مستقل** (یعنی بدون wrapper `+ SSH`) از یک listener محلی SOCKS5 به‌عنوان رابط downstream استفاده می‌کنند. خودِ تونل DNS سرتاسری احراز هویت می‌شود (handshake مبتنی بر Noise / Curve25519 — پس لینک تونل واقعاً برقرار است)، اما آنچه **بعد از** ترمیناتور سمت سرور اتفاق می‌افتد — یعنی forwardکردن واقعی به اینترنت آزاد — یک SOCKS5 / فوروارد ساده‌ی بدون تست end-to-end است. بنابراین یک پروفایل DNSTT/NoizDNS/VayDNS هم می‌تواند **«Connected» نشان دهد در حالی که ترافیک واقعی بی‌سروصدا fail می‌شود** اگر forwardکننده‌ی سمت سرور خراب یا جغرافیا-محدود باشد. حالت‌های **`+ SSH`** (یعنی DNSTT+SSH، NoizDNS+SSH، VayDNS+SSH) این موضوع را حل می‌کنند: یک نشست واقعی SSH از *داخل* تونل DNS رد می‌کنند و handshake SSH فقط زمانی کامل می‌شود که سرور واقعاً بتواند ترافیک را به مقصد برساند — به این ترتیب گارانتی liveness بازمی‌گردد.

**نتیجه‌ی عملی:**

- حالت SOCKS5 را یک **آداپتور انتقال** برای پراکسی‌ای که از قبل به آن اعتماد دارید بدانید، نه یک تست تونل. اگر پراکسی خراب یا جغرافیا-محدود باشد، «Connected» سبز می‌بینید بدون اینکه یک بایت رد و بدل شود.
- برای یک تونل واقعیِ ضد سانسور، **SSH** یا یکی از حالت‌های SSH-wrapped (NoizDNS+SSH، Slipstream+SSH، VLESS+SSH، NaiveProxy+SSH و …) را ترجیح دهید — این‌ها وقتی چیزی خراب است شکست را آشکار اعلام می‌کنند.
- اگر مجبورید SOCKS5 ساده استفاده کنید، تا حد ممکن **SSH را روی آن سوار کنید** — خانواده‌ی `+ SSH` از پراکسی SOCKS5 به‌عنوان transport استفاده می‌کند و یک نشست واقعی SSH از داخلش رد می‌کند. به این ترتیب گارانتی‌های احراز هویت و liveness بازمی‌گردند.

### DOH
- **DoH Server URL** — مثل `https://cloudflare-dns.com/dns-query`
- *(DOH فقط DNS را رمزنگاری می‌کند — ترافیک معمولی شما عوض نمی‌شود.)*

### Tor (نسخه Full)
- **Bridge type** — Snowflake / obfs4 / Meek / Direct / لاین‌های bridge سفارشی
- **Auto-detect Best Bridge** — اپ بهترین را خودش انتخاب می‌کند

---

## ۱۲. عیب‌یابی

| نشانه | راه‌حل |
|-------|------|
| اصلاً وصل نمی‌شود | **اسکنر** را اجرا کن، ریزالورها را عوض کن؛ DNS Transport را عوض کن (UDP → DoT → DoH)؛ به‌جای DNSTT از **NoizDNS** استفاده کن |
| وصل می‌شود ولی چند ثانیه بعد قطع می‌شود | **VPN MTU** را پایین بیار (1280)، **DNS Workers = 1** یا حالت *per-query* |
| وصل است ولی اینترنت نیست | **Disable QUIC** را روشن کن؛ **Auto-reconnect** را تست کن |
| اندروید SlipNet را در پس‌زمینه می‌کشد | تنظیمات → **بهینه‌سازی باتری** → SlipNet را بهینه نکن |
| یوتیوب / استریم بافر می‌کند | **Disable QUIC**؛ **Max Query Size** را روی تونل DNS کم کن؛ **Slipstream** یا **VLESS** را امتحان کن |
| محیط DPI سختگیر | از **NoizDNS + SSH**، **VLESS + SNI Fragmentation**، یا **Tor + Snowflake** (Full) استفاده کن |
| VLESS از Cloudflare تایم‌اوت می‌شود | **CDN IP** را روی یک IP تمیز معروف Cloudflare بگذار؛ **TLS SNI** باید با گواهی CF تو بخواند |
| SOCKS5 می‌گوید «Connected» ولی اینترنت نیست | پراکسی ریموت واقعاً به اینترنت آزاد دسترسی ندارد — SOCKS5 تست end-to-end ندارد. پراکسی را مستقل تست کنید، یا با SSH دور آن را بپیچید (از حالت `+ SSH` استفاده کنید) تا خرابی آشکار شود. |
| می‌خوام لاگ به پشتیبانی بدم | تنظیمات → **Debug logging** → ریپروی مشکل → **Export logs** |

---

## ۱۳. اشتراک‌گذاری و پشتیبان

- **اشتراک یک پروفایل**: روی پروفایل بزنید → منو → **Export** → URI `slipnet://` یا JSON.
- **خروجی همه**: منوی صفحه‌ی اصلی → **Export All Profiles** (ساده) یا **Export All (Encrypted)** با رمز.
- **بکاپ تنظیمات**: تنظیمات → منو → **Export Settings**.
- **اشتراک APK** با دوستان از طریق بلوتوث از منوی صفحه‌ی اصلی (مفید موقع قطعی اینترنت).

### انواع URI کانفیگ

SlipNet سه نوع URI برای خروجی دارد. این‌ها **هم‌ارز نیستند** — مدل امنیتی هرکدام فرق می‌کند.

| فرمت | چیست | کلید رمزنگاری |
|---|---|---|
| `slipnet://` | پروفایل ساده‌ی base64 | ندارد — هرکسی می‌تواند بخواند |
| `slipnet-enc://` | پروفایل تکیِ **قفل‌شده** (مخصوص گیرنده‌ی خاص) | کلید درون‌برنامه‌ای SlipNet |
| `slipnet-bundle-enc://` | بسته‌ی چندپروفایلی، رمز شده با رمز عبور | از رمز عبور خود شما مشتق می‌شود |

**`slipnet://`** — هرکسی با base64 می‌تواند بخواند. فقط برای گیرنده‌ی مورد اعتماد.

**`slipnet-enc://`** — وقتی یک پروفایل تکی را با قفل خروجی می‌گیرید (رمز، تاریخ انقضا اختیاری، قید به یک دستگاه، مخفی‌سازی resolverها، عدم اجازه‌ی بازنشر). محتوا با AES-256-GCM رمز می‌شود، **اما کلید AES درون اپ SlipNet جاسازی شده** و از رمز شما مشتق نمی‌شود. رمزی که می‌گذارید توسط اپ گیرنده بررسی می‌شود و فقط **نحوه‌ی استفاده** را کنترل می‌کند (فقط استفاده، عدم ویرایش، انقضا، قید به دستگاه، مخفی‌بودن resolverها). محرمانگی کانفیگ در برابر کسی که اپ را نصب دارد تأمین نمی‌شود. این را یک ابزار **کنترل اشتراک‌گذاری** بدانید، نه محرمانگی واقعی.

**`slipnet-bundle-enc://`** — توسط **Export All (Encrypted)** ساخته می‌شود. این یکی واقعاً با رمز عبور خودتان رمزنگاری می‌شود و برای پشتیبان‌گیری مناسب است.

### ⚠️ حتی کانفیگ رمزشده هم نباید در فضای عمومی منتشر شود

رمزنگاریِ بایت‌های کانفیگ، **هویت** سرور، دامنه یا CDN شما را پنهان نمی‌کند. به محض اینکه یک لینک `slipnet-enc://` در کانال عمومی منتشر شود:

- هرکسی که APK SlipNet را داشته باشد می‌تواند آن را باز کند و دامنه، IP، SNI، CDN host و credential را ببیند.
- سامانه‌های سانسور، کانال‌های عمومی را برای کانفیگ‌های جدید رصد می‌کنند و دامنه/IP را در عرض چند ساعت بلاک می‌کنند.
- خود دامنه از این به بعد یک هدف دائمی blocklist است؛ رمزنگاری نمی‌تواند آن را برگرداند.

اگر **VPS یا دامنه‌ی خود را داخل همان کشوری که می‌خواهید سانسورش را دور بزنید خریده‌اید**، خطر دو چندان است:

- ثبت‌کننده‌های دامنه و سرویس‌دهنده‌های هاستینگ داخلی می‌توانند **مجبور به افشای صاحب، توقف سرویس یا تحویل لاگ شوند**.
- دامنه‌های تحت TLD ملی (مثل `.ir`، `.cn`، `.ru` یا هر TLD تحت همان قضاوت قانونی) را می‌توان به‌صورت اداری توقیف کرد، فارغ از اینکه تونل شما چقدر رمزنگاری قوی دارد.
- VPS یا دامنه‌ای که قابل ردیابی به شخصی داخل کشور باشد، علاوه بر کانفیگ، **اپراتور** را هم لو می‌دهد.

قواعد کلی:

- برای پخش گسترده‌تر، روی **VPS خریداری‌شده از خارج کشور** و دامنه‌ی ثبت‌شده در **ریجیسترار خارج از کشور** میزبانی کنید. روی همان VPS، **Warp را از داخل SlipGate فعال کنید** تا ترافیک خروجی سرور از پشت Cloudflare Warp عبور کند و IP واقعی VPS لو نرود.
- کانفیگ را **خصوصی** بفرستید (تک به تک، در چت رمزنگاری‌شده‌ی end-to-end) — نه در گروه، نه در سایت، نه پین‌شده در کانال.
- قابلیت‌های قفل `slipnet-enc://` (انقضا، قید به دستگاه، مخفی‌بودن resolverها، عدم بازنشر) را برای **کند کردن سوءاستفاده** به کار ببرید، نه برای اینکه کانفیگ را عمومی کنید.

> ⚠️ لینک `slipnet://` حاوی اطلاعات حساس شماست؛ هرگز آن را در گروه عمومی نگذارید.
>
> ⚠️ لینک `slipnet-enc://` هم **برای انتشار عمومی امن نیست**: هر کسی که اپ SlipNet را داشته باشد می‌تواند آن را رمزگشایی کند. قفل، فقط *نحوه‌ی استفاده* را محدود می‌کند و **محرمانگی محتوا را تضمین نمی‌کند**. رمزنگاری از credentialها در حین انتقال محافظت می‌کند، اما به محض اینکه لینک علنی شد، **هویت دامنه و سرور شما لو می‌رود** و رمزنگاری نمی‌تواند جلویش را بگیرد.

---

## ۱۴. حمایت مالی

توسعه‌ی SlipNet داوطلبانه و بدون درآمد است. اگر این اپ به شما کمک کرده، آدرس‌های دونیت (BEP-20 / ERC-20 / Arbitrum، Monero و…) همیشه به‌روز در README پروژه روی گیت‌هاب نگه‌داری می‌شوند: <https://github.com/anonvector/SlipNet#donations>

---

## ۱۵. نکات امنیتی

- SlipNet را فقط از **کانال رسمی تلگرام** یا **گیت‌هاب** دانلود کنید.
- لینک `slipnet://` خود را با غریبه‌ها به اشتراک نگذارید.
- موقع پشتیبان‌گیری از **Export رمزشده** استفاده کنید.
- اصالت سرور را با **Prism** (اسکن سرور-تأییدشده) اعتبارسنجی کنید — با SlipGate کار می‌کند.
- اگر سرور خودتان را اجرا می‌کنید: هیچ‌وقت `root` یا هر اکانت shell را به‌عنوان credential VPN ندهید — همیشه با SlipGate کاربر مخصوص بسازید.

کانال: [@SlipNet_app](https://t.me/SlipNet_app)
سورس: https://github.com/anonvector/SlipNet
