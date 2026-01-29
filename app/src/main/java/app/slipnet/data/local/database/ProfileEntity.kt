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
    val domain: String,

    @ColumnInfo(name = "resolvers_json")
    val resolversJson: String,

    @ColumnInfo(name = "authoritative_mode")
    val authoritativeMode: Boolean = false,

    @ColumnInfo(name = "certificate_path")
    val certificatePath: String? = null,

    @ColumnInfo(name = "keep_alive_interval")
    val keepAliveInterval: Int = 400,

    @ColumnInfo(name = "congestion_control")
    val congestionControl: String = "bbr",

    @ColumnInfo(name = "is_active")
    val isActive: Boolean = false,

    @ColumnInfo(name = "created_at")
    val createdAt: Long,

    @ColumnInfo(name = "updated_at")
    val updatedAt: Long
)
