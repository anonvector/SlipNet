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
    val keepAliveInterval: Int = 200,

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

    @ColumnInfo(name = "use_server_dns", defaultValue = "0")
    val useServerDns: Boolean = false,

    @ColumnInfo(name = "doh_url", defaultValue = "")
    val dohUrl: String = "",

    @ColumnInfo(name = "last_connected_at", defaultValue = "0")
    val lastConnectedAt: Long = 0,

    @ColumnInfo(name = "dns_transport", defaultValue = "udp")
    val dnsTransport: String = "udp"
)
