package app.slipnet.domain.model

import app.slipnet.BuildConfig

data class ServerProfile(
    val id: Long = 0,
    val name: String,
    val domain: String = "",
    val resolvers: List<DnsResolver> = emptyList(),
    val authoritativeMode: Boolean = false,
    val keepAliveInterval: Int = 5000,
    val congestionControl: CongestionControl = CongestionControl.BBR,
    val gsoEnabled: Boolean = false,
    val tcpListenPort: Int = 1080,
    val tcpListenHost: String = "127.0.0.1",
    val socksUsername: String? = null,
    val socksPassword: String? = null,
    val isActive: Boolean = false,
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis(),
    // Tunnel type selection (DNSTT is more stable)
    val tunnelType: TunnelType = TunnelType.DNSTT,
    // DNSTT-specific fields
    val dnsttPublicKey: String = "",
    // SSH tunnel fields (used for SSH-only and DNSTT+SSH tunnel types)
    val sshUsername: String = "",
    val sshPassword: String = "",
    val sshPort: Int = 22,
    // SSH host as seen from DNSTT server (for DNSTT+SSH, default 127.0.0.1 for co-located servers)
    val sshHost: String = "127.0.0.1",
    // DoH (DNS over HTTPS) server URL
    val dohUrl: String = "",
    // Timestamp of last successful connection (0 = never connected)
    val lastConnectedAt: Long = 0,
    // DNS transport for DNSTT tunnel types (UDP, DoH, DoT)
    val dnsTransport: DnsTransport = DnsTransport.UDP,
    // SSH authentication type (password or key)
    val sshAuthType: SshAuthType = SshAuthType.PASSWORD,
    // SSH private key (PEM content)
    val sshPrivateKey: String = "",
    // SSH key passphrase (optional)
    val sshKeyPassphrase: String = "",
    // Custom Tor bridge lines (one per line). Empty = use built-in Snowflake.
    // Transport is auto-detected from bridge line prefix (obfs4, webtunnel, meek_lite, etc.)
    val torBridgeLines: String = "",
    // User-defined sort order for profile list (lower = higher in list)
    val sortOrder: Int = 0,
    // When true, DNSTT uses aggressive query rates (authoritative mode for own servers)
    val dnsttAuthoritative: Boolean = false,
    // NaiveProxy fields (NAIVE_SSH tunnel type)
    val naivePort: Int = 443,
    val naiveUsername: String = "",
    val naivePassword: String = "",
    // Locked profile (UI-level only — full data stays in DB for VPN service)
    val isLocked: Boolean = false,
    val lockPasswordHash: String = "",
    // Locked profile enhancements (v16)
    val expirationDate: Long = 0,
    val allowSharing: Boolean = false,
    val boundDeviceId: String = "",
    // NoizDNS stealth mode: trades speed for DPI resistance (jitter, slow polling, cover traffic)
    val noizdnsStealth: Boolean = false,
    // DNS query payload size cap (KCP MTU). 0 = full capacity (matches DB default).
    // Lower values produce smaller, less conspicuous DNS queries.
    val dnsPayloadSize: Int = 0,
    // When true, resolvers are hidden from the user (set during import of hidden-resolver profiles)
    val resolversHidden: Boolean = false,
    // Original default resolvers from import (preserved when user overrides with custom resolvers)
    val defaultResolvers: List<DnsResolver> = emptyList(),
    // SOCKS5 proxy server port (for SOCKS5 tunnel type)
    val socks5ServerPort: Int = 1080,
    // VayDNS: enable dnstt wire-format compatibility (8-byte ClientID, padding prefixes)
    val vaydnsDnsttCompat: Boolean = false,
    // VayDNS: DNS record type for downstream data (txt, cname, a, aaaa, mx, ns, srv, null, caa)
    val vaydnsRecordType: String = "txt",
    // VayDNS: maximum QNAME wire length (controls query size on the wire, default 101)
    val vaydnsMaxQnameLen: Int = 101,
    // VayDNS: DNS query rate limit (queries per second, 0 = unlimited)
    val vaydnsRps: Double = 0.0,
    // VayDNS advanced: session idle timeout in seconds (0 = default: 10s, or 120s with dnsttCompat)
    val vaydnsIdleTimeout: Int = 0,
    // VayDNS advanced: keepalive interval in seconds (0 = default: 2s, or 10s with dnsttCompat)
    val vaydnsKeepalive: Int = 0,
    // VayDNS advanced: per-query UDP response timeout in ms (0 = default ~500ms)
    val vaydnsUdpTimeout: Int = 0,
    // VayDNS advanced: max number of data labels in query name (0 = unlimited)
    val vaydnsMaxNumLabels: Int = 0,
    // VayDNS advanced: ClientID size in bytes (0 = default 2, ignored when dnsttCompat is true)
    val vaydnsClientIdSize: Int = 0,
    // Pinned to top of profile list
    val isPinned: Boolean = false,
    // SSH over TLS (stunnel): wrap SSH connection in TLS for firewall bypass / domain fronting
    val sshTlsEnabled: Boolean = false,
    // Custom SNI hostname for TLS ClientHello (empty = use server hostname)
    val sshTlsSni: String = "",
    // SSH over HTTP CONNECT proxy: proxy address, port, and custom Host header
    val sshHttpProxyHost: String = "",
    val sshHttpProxyPort: Int = 8080,
    // Custom Host header for HTTP CONNECT request (empty = use SSH server host:port)
    val sshHttpProxyCustomHost: String = "",
    // SSH over WebSocket: tunnel SSH through a WebSocket connection (for CDN facades, xray, etc.)
    val sshWsEnabled: Boolean = false,
    // WebSocket endpoint path (default "/")
    val sshWsPath: String = "/",
    // Use TLS for WebSocket (wss:// vs ws://)
    val sshWsUseTls: Boolean = true,
    // Custom Host header for WebSocket upgrade request (empty = use server hostname)
    val sshWsCustomHost: String = "",
    // Raw payload sent on the TCP socket before the SSH handshake (for DPI bypass).
    // Supports escape sequences (\r, \n) and placeholders ([host], [port]).
    val sshPayload: String = "",
    // Multi-resolver mode: "fanout" (reliable, send to all) or "roundrobin" (fast, bandwidth aggregation)
    val resolverMode: ResolverMode = ResolverMode.ROUND_ROBIN,
    // Round-robin spread count: how many resolvers each query is sent to in fast mode (1=no duplicates, default 3)
    val rrSpreadCount: Int = 3,
    // VLESS fields (CDN-based VLESS tunnel with SNI fragmentation)
    val vlessUuid: String = "",
    val vlessSecurity: String = "tls",
    val vlessTransport: String = "ws",
    val vlessWsPath: String = "/",
    // CDN IP to connect to (e.g. Cloudflare clean IP)
    val cdnIp: String = "",
    val cdnPort: Int = 443,
    // SNI fragmentation for DPI bypass on TLS connections to CDN
    val sniFragmentEnabled: Boolean = true,
    // Fragment strategy. Default "micro" — strongest against reassembling
    // DPI (1-byte TLS records + TCP_MAXSEG=70). Users on permissive networks
    // can downgrade to "multi" / "sni_split" via the profile editor to save
    // throughput.
    val sniFragmentStrategy: String = "micro",
    // Delay between fragments in milliseconds. 300ms is a safer default
    // against reassembling DPI; drop to ~50–100 on cooperative networks.
    val sniFragmentDelayMs: Int = 300,
    // Low TTL applied to decoy packets in `fake` / `disorder` strategies.
    // Must die between the local DPI and the CDN edge; 8 is the ByeDPI default.
    val sniSpoofTtl: Int = 8,
    // Decoy hostname written into the fake ClientHello in `fake` strategy.
    // Empty = use the built-in default ("www.google.com"). Truncated/space-padded
    // to match the real hostname length so record byte offsets stay identical.
    val fakeDecoyHost: String = "",
    // TCP MSS cap on the CDN socket. 0 = auto (applied only in `micro` / CH-padding).
    // 40–1400 = explicit cap that forces sub-record TCP fragmentation across every
    // TLS record, useful against DPI that inspects per-segment instead of reassembling.
    // Trade-off: smaller MSS = more segments + slower post-handshake throughput.
    val tcpMaxSeg: Int = 0,
    // TLS SNI sent in the ClientHello. Empty = fall back to [domain] (the WS
    // Host). Set explicitly when the CDN cert hostname differs from the WS
    // Host, or — against a direct server you control — to any decoy string
    // for DPI evasion (cert verification is permissive). This is the single
    // SNI field; matches V2Ray/Xray's streamSettings.tlsSettings.serverName.
    val vlessSni: String = "",
    // DPI evasion: pad ClientHello to ~517 bytes with TLS padding extension
    val chPaddingEnabled: Boolean = false,
    // DPI evasion: add browser-like headers and randomize order in WS upgrade request.
    // Defaults on: cheap (a handful of bytes per connection) and useful against
    // DPI that fingerprints by WS upgrade header shape.
    val wsHeaderObfuscation: Boolean = true,
    // DPI evasion: send random WS ping frames as cover traffic during relay
    val wsPaddingEnabled: Boolean = false
) {
    val isExpired: Boolean get() = expirationDate > 0 && System.currentTimeMillis() > expirationDate
}

data class DnsResolver(
    val host: String,
    val port: Int = 53,
    val authoritative: Boolean = false
)

enum class CongestionControl(val value: String) {
    BBR("bbr"),
    DCUBIC("dcubic");

    companion object {
        fun fromValue(value: String): CongestionControl {
            return entries.find { it.value == value } ?: BBR
        }
    }
}

enum class TunnelType(val value: String, val displayName: String) {
    SLIPSTREAM("slipstream", "Slipstream"),
    SLIPSTREAM_SSH("slipstream_ssh", "Slipstream + SSH"),
    DNSTT("dnstt", "DNSTT"),
    DNSTT_SSH("dnstt_ssh", "DNSTT + SSH"),
    NOIZDNS("sayedns", "NoizDNS"),
    NOIZDNS_SSH("sayedns_ssh", "NoizDNS + SSH"),
    SSH("ssh", "SSH"),
    DOH("doh", "DOH (DNS over HTTPS)"),
    SNOWFLAKE("snowflake", "Tor"),
    NAIVE_SSH("naive_ssh", "NaiveProxy + SSH"),
    NAIVE("naive", "NaiveProxy"),
    SOCKS5("socks5", "SOCKS5 Proxy"),
    VAYDNS("vaydns", "VayDNS"),
    VAYDNS_SSH("vaydns_ssh", "VayDNS + SSH"),
    VLESS("vless", "VLESS");

    companion object {
        fun fromValue(value: String): TunnelType {
            return entries.find { it.value == value } ?: DNSTT
        }
    }
}

fun TunnelType.isAvailable(): Boolean = when (this) {
    TunnelType.SNOWFLAKE -> BuildConfig.INCLUDE_TOR
    TunnelType.NAIVE, TunnelType.NAIVE_SSH -> BuildConfig.INCLUDE_NAIVE
    else -> true
}

enum class SshAuthType(val value: String) {
    PASSWORD("password"),
    KEY("key");

    companion object {
        fun fromValue(value: String): SshAuthType {
            return entries.find { it.value == value } ?: PASSWORD
        }
    }
}

enum class ResolverMode(val value: String, val displayName: String) {
    FANOUT("fanout", "Reliable"),
    ROUND_ROBIN("roundrobin", "Fast");

    companion object {
        fun fromValue(value: String): ResolverMode {
            return entries.find { it.value == value } ?: FANOUT
        }
    }
}

enum class DnsTransport(val value: String, val displayName: String) {
    UDP("udp", "UDP"),
    TCP("tcp", "TCP"),
    DOT("dot", "DoT"),
    DOH("doh", "DoH");

    companion object {
        fun fromValue(value: String): DnsTransport {
            return entries.find { it.value == value } ?: UDP
        }
    }
}


