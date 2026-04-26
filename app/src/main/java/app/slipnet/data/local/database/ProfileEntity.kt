package app.slipnet.data.local.database

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "server_profiles")
data class ProfileEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    @ColumnInfo(name = "name")
    val name: String,

    @ColumnInfo(name = "domain")
    val domain: String = "",

    @ColumnInfo(name = "resolvers_json")
    val resolversJson: String = "[]",

    @ColumnInfo(name = "authoritative_mode")
    val authoritativeMode: Boolean = false,

    @ColumnInfo(name = "keep_alive_interval")
    val keepAliveInterval: Int = 5000,

    @ColumnInfo(name = "congestion_control")
    val congestionControl: String = "bbr",

    @ColumnInfo(name = "gso_enabled")
    val gsoEnabled: Boolean = false,

    @ColumnInfo(name = "tcp_listen_port")
    val tcpListenPort: Int = 1080,

    @ColumnInfo(name = "tcp_listen_host")
    val tcpListenHost: String = "127.0.0.1",

    @ColumnInfo(name = "socks_username", defaultValue = "")
    val socksUsername: String = "",

    @ColumnInfo(name = "socks_password", defaultValue = "")
    val socksPassword: String = "",

    @ColumnInfo(name = "is_active")
    val isActive: Boolean = false,

    @ColumnInfo(name = "created_at")
    val createdAt: Long,

    @ColumnInfo(name = "updated_at")
    val updatedAt: Long,

    // Tunnel type: "slipstream" or "dnstt"
    @ColumnInfo(name = "tunnel_type", defaultValue = "slipstream")
    val tunnelType: String = "slipstream",

    // DNSTT-specific: Noise protocol public key (hex encoded)
    @ColumnInfo(name = "dnstt_public_key", defaultValue = "")
    val dnsttPublicKey: String = "",

    // SSH tunnel fields
    @ColumnInfo(name = "ssh_enabled", defaultValue = "0")
    val sshEnabled: Boolean = false,

    @ColumnInfo(name = "ssh_username", defaultValue = "")
    val sshUsername: String = "",

    @ColumnInfo(name = "ssh_password", defaultValue = "")
    val sshPassword: String = "",

    @ColumnInfo(name = "ssh_port", defaultValue = "22")
    val sshPort: Int = 22,

    @ColumnInfo(name = "forward_dns_through_ssh", defaultValue = "0")
    val forwardDnsThroughSsh: Boolean = false,

    @ColumnInfo(name = "ssh_host", defaultValue = "127.0.0.1")
    val sshHost: String = "127.0.0.1",

    @ColumnInfo(name = "doh_url", defaultValue = "")
    val dohUrl: String = "",

    @ColumnInfo(name = "last_connected_at", defaultValue = "0")
    val lastConnectedAt: Long = 0,

    @ColumnInfo(name = "dns_transport", defaultValue = "udp")
    val dnsTransport: String = "udp",

    @ColumnInfo(name = "ssh_auth_type", defaultValue = "password")
    val sshAuthType: String = "password",

    @ColumnInfo(name = "ssh_private_key", defaultValue = "")
    val sshPrivateKey: String = "",

    @ColumnInfo(name = "ssh_key_passphrase", defaultValue = "")
    val sshKeyPassphrase: String = "",

    @ColumnInfo(name = "tor_bridge_lines", defaultValue = "")
    val torBridgeLines: String = "",

    @ColumnInfo(name = "sort_order", defaultValue = "0")
    val sortOrder: Int = 0,

    @ColumnInfo(name = "dnstt_authoritative", defaultValue = "0")
    val dnsttAuthoritative: Boolean = false,

    @ColumnInfo(name = "naive_port", defaultValue = "443")
    val naivePort: Int = 443,

    @ColumnInfo(name = "naive_username", defaultValue = "")
    val naiveUsername: String = "",

    @ColumnInfo(name = "naive_password", defaultValue = "")
    val naivePassword: String = "",

    @ColumnInfo(name = "is_locked", defaultValue = "0")
    val isLocked: Boolean = false,

    @ColumnInfo(name = "lock_password_hash", defaultValue = "")
    val lockPasswordHash: String = "",

    @ColumnInfo(name = "expiration_date", defaultValue = "0")
    val expirationDate: Long = 0,

    @ColumnInfo(name = "allow_sharing", defaultValue = "0")
    val allowSharing: Boolean = false,

    @ColumnInfo(name = "bound_device_id", defaultValue = "")
    val boundDeviceId: String = "",

    @ColumnInfo(name = "noizdns_stealth", defaultValue = "0")
    val noizdnsStealth: Boolean = false,

    @ColumnInfo(name = "dns_payload_size", defaultValue = "0")
    val dnsPayloadSize: Int = 0,

    @ColumnInfo(name = "resolvers_hidden", defaultValue = "0")
    val resolversHidden: Boolean = false,

    @ColumnInfo(name = "default_resolvers_json", defaultValue = "[]")
    val defaultResolversJson: String = "[]",

    @ColumnInfo(name = "socks5_server_port", defaultValue = "1080")
    val socks5ServerPort: Int = 1080,

    @ColumnInfo(name = "vaydns_dnstt_compat", defaultValue = "0")
    val vaydnsDnsttCompat: Boolean = false,

    @ColumnInfo(name = "vaydns_record_type", defaultValue = "txt")
    val vaydnsRecordType: String = "txt",

    @ColumnInfo(name = "vaydns_max_qname_len", defaultValue = "101")
    val vaydnsMaxQnameLen: Int = 101,

    @ColumnInfo(name = "vaydns_rps", defaultValue = "0.0")
    val vaydnsRps: Double = 0.0,

    @ColumnInfo(name = "vaydns_idle_timeout", defaultValue = "0")
    val vaydnsIdleTimeout: Int = 0,

    @ColumnInfo(name = "vaydns_keepalive", defaultValue = "0")
    val vaydnsKeepalive: Int = 0,

    @ColumnInfo(name = "vaydns_udp_timeout", defaultValue = "0")
    val vaydnsUdpTimeout: Int = 0,

    @ColumnInfo(name = "vaydns_max_num_labels", defaultValue = "0")
    val vaydnsMaxNumLabels: Int = 0,

    @ColumnInfo(name = "vaydns_clientid_size", defaultValue = "0")
    val vaydnsClientIdSize: Int = 0,

    @ColumnInfo(name = "is_pinned", defaultValue = "0")
    val isPinned: Boolean = false,

    // SSH over TLS (stunnel-style wrapping)
    @ColumnInfo(name = "ssh_tls_enabled", defaultValue = "0")
    val sshTlsEnabled: Boolean = false,

    @ColumnInfo(name = "ssh_tls_sni", defaultValue = "")
    val sshTlsSni: String = "",

    // SSH over HTTP CONNECT proxy
    @ColumnInfo(name = "ssh_http_proxy_host", defaultValue = "")
    val sshHttpProxyHost: String = "",

    @ColumnInfo(name = "ssh_http_proxy_port", defaultValue = "8080")
    val sshHttpProxyPort: Int = 8080,

    @ColumnInfo(name = "ssh_http_proxy_custom_host", defaultValue = "")
    val sshHttpProxyCustomHost: String = "",

    // SSH over WebSocket
    @ColumnInfo(name = "ssh_ws_enabled", defaultValue = "0")
    val sshWsEnabled: Boolean = false,

    @ColumnInfo(name = "ssh_ws_path", defaultValue = "/")
    val sshWsPath: String = "/",

    @ColumnInfo(name = "ssh_ws_use_tls", defaultValue = "1")
    val sshWsUseTls: Boolean = true,

    @ColumnInfo(name = "ssh_ws_custom_host", defaultValue = "")
    val sshWsCustomHost: String = "",

    // Raw payload sent before SSH handshake (DPI bypass)
    @ColumnInfo(name = "ssh_payload", defaultValue = "")
    val sshPayload: String = "",

    // Multi-resolver mode: "fanout" or "roundrobin"
    @ColumnInfo(name = "resolver_mode", defaultValue = "fanout")
    val resolverMode: String = "fanout",

    // Round-robin spread count: how many resolvers each query is sent to in fast mode
    @ColumnInfo(name = "rr_spread_count", defaultValue = "3")
    val rrSpreadCount: Int = 3,

    // VLESS fields
    @ColumnInfo(name = "vless_uuid", defaultValue = "")
    val vlessUuid: String = "",

    @ColumnInfo(name = "vless_security", defaultValue = "tls")
    val vlessSecurity: String = "tls",

    @ColumnInfo(name = "vless_transport", defaultValue = "ws")
    val vlessTransport: String = "ws",

    @ColumnInfo(name = "vless_ws_path", defaultValue = "/")
    val vlessWsPath: String = "/",

    @ColumnInfo(name = "cdn_ip", defaultValue = "")
    val cdnIp: String = "",

    @ColumnInfo(name = "cdn_port", defaultValue = "443")
    val cdnPort: Int = 443,

    // SNI fragmentation
    @ColumnInfo(name = "sni_fragment_enabled", defaultValue = "1")
    val sniFragmentEnabled: Boolean = true,

    @ColumnInfo(name = "sni_fragment_strategy", defaultValue = "sni_split")
    val sniFragmentStrategy: String = "sni_split",

    @ColumnInfo(name = "sni_fragment_delay_ms", defaultValue = "100")
    val sniFragmentDelayMs: Int = 100,

    @ColumnInfo(name = "sni_spoof_ttl", defaultValue = "8")
    val sniSpoofTtl: Int = 8,

    @ColumnInfo(name = "vless_sni", defaultValue = "")
    val vlessSni: String = "",

    // Legacy column retained for Room schema compatibility only.
    // Prior versions conflated "real SNI" and "DPI-evasion SNI override" into
    // this one field; v39 migrated the real values into vless_sni and cleared
    // this column. Kept nullable-empty going forward; drop in a future table
    // recreation migration when convenient.
    @ColumnInfo(name = "fake_sni", defaultValue = "")
    val fakeSni: String = "",

    @ColumnInfo(name = "fake_decoy_host", defaultValue = "")
    val fakeDecoyHost: String = "",

    @ColumnInfo(name = "tcp_max_seg", defaultValue = "0")
    val tcpMaxSeg: Int = 0,

    // DPI evasion options
    @ColumnInfo(name = "ch_padding_enabled", defaultValue = "0")
    val chPaddingEnabled: Boolean = false,

    @ColumnInfo(name = "ws_header_obfuscation", defaultValue = "0")
    val wsHeaderObfuscation: Boolean = false,

    @ColumnInfo(name = "ws_padding_enabled", defaultValue = "0")
    val wsPaddingEnabled: Boolean = false
)
