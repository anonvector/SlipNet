package app.slipnet.data.local.database

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
    entities = [ProfileEntity::class],
    version = 16,
    exportSchema = true
)
abstract class SlipNetDatabase : RoomDatabase() {
    abstract fun profileDao(): ProfileDao

    companion object {
        const val DATABASE_NAME = "slipstream_database"

        val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE server_profiles ADD COLUMN ssh_port INTEGER NOT NULL DEFAULT 22")
            }
        }

        val MIGRATION_6_7 = object : Migration(6, 7) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE server_profiles ADD COLUMN forward_dns_through_ssh INTEGER NOT NULL DEFAULT 0")
            }
        }

        val MIGRATION_7_8 = object : Migration(7, 8) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE server_profiles ADD COLUMN ssh_host TEXT NOT NULL DEFAULT '127.0.0.1'")
            }
        }

        val MIGRATION_8_9 = object : Migration(8, 9) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // use_server_dns column removed — no-op migration to preserve chain
            }
        }

        val MIGRATION_9_10 = object : Migration(9, 10) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE server_profiles ADD COLUMN doh_url TEXT NOT NULL DEFAULT ''")
            }
        }

        val MIGRATION_10_11 = object : Migration(10, 11) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE server_profiles ADD COLUMN last_connected_at INTEGER NOT NULL DEFAULT 0")
            }
        }

        val MIGRATION_11_12 = object : Migration(11, 12) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE server_profiles ADD COLUMN dns_transport TEXT NOT NULL DEFAULT 'udp'")
            }
        }

        val MIGRATION_12_13 = object : Migration(12, 13) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE server_profiles ADD COLUMN ssh_auth_type TEXT NOT NULL DEFAULT 'password'")
                db.execSQL("ALTER TABLE server_profiles ADD COLUMN ssh_private_key TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE server_profiles ADD COLUMN ssh_key_passphrase TEXT NOT NULL DEFAULT ''")
            }
        }

        val MIGRATION_13_14 = object : Migration(13, 14) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE server_profiles ADD COLUMN tor_bridge_lines TEXT NOT NULL DEFAULT ''")
            }
        }

        val MIGRATION_14_15 = object : Migration(14, 15) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE server_profiles ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0")
                // Assign sequential sort_order preserving current updated_at DESC order
                db.execSQL("""
                    UPDATE server_profiles SET sort_order = (
                        SELECT COUNT(*) FROM server_profiles AS sp2
                        WHERE sp2.updated_at > server_profiles.updated_at
                           OR (sp2.updated_at = server_profiles.updated_at AND sp2.id < server_profiles.id)
                    )
                """.trimIndent())
            }
        }

        val MIGRATION_15_16 = object : Migration(15, 16) {
            override fun migrate(db: SupportSQLiteDatabase) {
                // Check if the deprecated use_server_dns column exists (was added in old
                // migration 8→9, later removed from Entity when it became a global setting).
                // Room requires exact schema match, so we must drop the orphaned column.
                val cursor = db.query("PRAGMA table_info(server_profiles)")
                var hasUseServerDns = false
                while (cursor.moveToNext()) {
                    val nameIdx = cursor.getColumnIndex("name")
                    if (nameIdx >= 0 && cursor.getString(nameIdx) == "use_server_dns") {
                        hasUseServerDns = true
                        break
                    }
                }
                cursor.close()

                if (hasUseServerDns) {
                    // Recreate table without use_server_dns, adding dnstt_authoritative.
                    // ALTER TABLE DROP COLUMN requires SQLite 3.35.0+ (Android 13+),
                    // so we use the table-recreation approach for minSdk 24 compatibility.
                    db.execSQL("""
                        CREATE TABLE server_profiles_new (
                            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                            name TEXT NOT NULL,
                            domain TEXT NOT NULL,
                            resolvers_json TEXT NOT NULL,
                            authoritative_mode INTEGER NOT NULL,
                            keep_alive_interval INTEGER NOT NULL,
                            congestion_control TEXT NOT NULL,
                            gso_enabled INTEGER NOT NULL,
                            tcp_listen_port INTEGER NOT NULL,
                            tcp_listen_host TEXT NOT NULL,
                            socks_username TEXT NOT NULL DEFAULT '',
                            socks_password TEXT NOT NULL DEFAULT '',
                            is_active INTEGER NOT NULL,
                            created_at INTEGER NOT NULL,
                            updated_at INTEGER NOT NULL,
                            tunnel_type TEXT NOT NULL DEFAULT 'slipstream',
                            dnstt_public_key TEXT NOT NULL DEFAULT '',
                            ssh_enabled INTEGER NOT NULL DEFAULT 0,
                            ssh_username TEXT NOT NULL DEFAULT '',
                            ssh_password TEXT NOT NULL DEFAULT '',
                            ssh_port INTEGER NOT NULL DEFAULT 22,
                            forward_dns_through_ssh INTEGER NOT NULL DEFAULT 0,
                            ssh_host TEXT NOT NULL DEFAULT '127.0.0.1',
                            doh_url TEXT NOT NULL DEFAULT '',
                            last_connected_at INTEGER NOT NULL DEFAULT 0,
                            dns_transport TEXT NOT NULL DEFAULT 'udp',
                            ssh_auth_type TEXT NOT NULL DEFAULT 'password',
                            ssh_private_key TEXT NOT NULL DEFAULT '',
                            ssh_key_passphrase TEXT NOT NULL DEFAULT '',
                            tor_bridge_lines TEXT NOT NULL DEFAULT '',
                            sort_order INTEGER NOT NULL DEFAULT 0,
                            dnstt_authoritative INTEGER NOT NULL DEFAULT 0
                        )
                    """.trimIndent())
                    db.execSQL("""
                        INSERT INTO server_profiles_new (
                            id, name, domain, resolvers_json, authoritative_mode,
                            keep_alive_interval, congestion_control, gso_enabled,
                            tcp_listen_port, tcp_listen_host, socks_username, socks_password,
                            is_active, created_at, updated_at, tunnel_type, dnstt_public_key,
                            ssh_enabled, ssh_username, ssh_password, ssh_port,
                            forward_dns_through_ssh, ssh_host, doh_url, last_connected_at,
                            dns_transport, ssh_auth_type, ssh_private_key, ssh_key_passphrase,
                            tor_bridge_lines, sort_order
                        )
                        SELECT
                            id, name, domain, resolvers_json, authoritative_mode,
                            keep_alive_interval, congestion_control, gso_enabled,
                            tcp_listen_port, tcp_listen_host, socks_username, socks_password,
                            is_active, created_at, updated_at, tunnel_type, dnstt_public_key,
                            ssh_enabled, ssh_username, ssh_password, ssh_port,
                            forward_dns_through_ssh, ssh_host, doh_url, last_connected_at,
                            dns_transport, ssh_auth_type, ssh_private_key, ssh_key_passphrase,
                            tor_bridge_lines, sort_order
                        FROM server_profiles
                    """.trimIndent())
                    db.execSQL("DROP TABLE server_profiles")
                    db.execSQL("ALTER TABLE server_profiles_new RENAME TO server_profiles")
                } else {
                    // Column doesn't exist (fresh install path) — just add dnstt_authoritative
                    db.execSQL("ALTER TABLE server_profiles ADD COLUMN dnstt_authoritative INTEGER NOT NULL DEFAULT 0")
                }
            }
        }

    }
}
