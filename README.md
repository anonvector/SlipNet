# SlipNet

<p align="center">
  <img src="imgs/icon.png" alt="SlipNet Logo" width="200">
</p>

A fast, modern Android VPN client built with Jetpack Compose and Kotlin, featuring DNS tunneling with support for multiple protocols.

## Donate

If you want to support development:

- **USDT (BNB, ERC20)**: `0xd4140058389572D50dC8716e768e687C050Dd5C9`

## Tunnel Types

SlipNet supports multiple tunnel types with optional SSH chaining:

| Tunnel Type | Protocol | Description |
|-------------|----------|-------------|
| **DNSTT** | KCP + Noise | Stable and reliable DNS tunneling |
| **DNSTT + SSH** | KCP + Noise + SSH | DNSTT with SSH chaining for zero DNS leaks |
| **Slipstream** | QUIC | High-performance QUIC tunneling |
| **Slipstream + SSH** | QUIC + SSH | Slipstream with SSH chaining |
| **SSH** | SSH | Standalone SSH tunnel (no DNS tunneling) |
| **DOH** | DNS over HTTPS | DNS-only encryption via HTTPS (RFC 8484) |

**Note:** DNSTT is the default and recommended tunnel type for most users. SSH variants add an extra layer of encryption and can prevent DNS leaks.

## Features

- **Modern UI**: Built entirely with Jetpack Compose and Material 3 design
- **Multiple Tunnel Types**: DNSTT, Slipstream, SSH, and DOH with optional SSH chaining
- **SSH Tunneling**: Chain SSH through DNSTT or Slipstream, or use standalone SSH
- **DNS over HTTPS**: Encrypt DNS queries via HTTPS without tunneling other traffic
- **DNS Transport Selection**: Choose UDP, DoT, or DoH for DNSTT DNS resolution
- **SSH Cipher Selection**: Choose between AES-128-GCM, ChaCha20, and AES-128-CTR
- **DNS Server Scanning**: Automatically discover and test compatible DNS servers
- **Multiple Profiles**: Create and manage multiple server configurations
- **Configurable Proxy**: Set custom listen address and port
- **Quick Settings Tile**: Toggle VPN connection directly from the notification shade
- **Auto-connect on Boot**: Optionally reconnect VPN when device starts
- **APK Sharing**: Share the app via Bluetooth or other methods in case of internet shutdowns
- **Debug Logging**: Toggle detailed traffic logs for troubleshooting
- **Dark Mode**: Full support for system-wide dark theme

## Server Setup

To use this client, you must have a compatible server. Please configure your server in SOCKS or SSH mode using one of the following deployment scripts:

**DNSTT**:
[**dnstt-deploy**](https://github.com/bugfloyd/dnstt-deploy)

**SlipStream:**
[**slipstream-rust-deploy**](https://github.com/AliRezaBeigy/slipstream-rust-deploy)

## Screenshots

<!-- Add screenshots here -->

## Requirements

- Android 7.0 (API 24) or higher
- Android Studio Hedgehog (2023.1.1) or later
- JDK 17
- Rust toolchain (for building the native library)
- Android NDK 29

## Building

### Prerequisites

1. **Install Rust**
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Add Android targets**
   ```bash
   rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
   ```

3. **Set up OpenSSL for Android**

   OpenSSL will be automatically downloaded when you build for the first time. You can also set it up manually:
   ```bash
   ./gradlew setupOpenSsl
   ```

   This will download pre-built OpenSSL libraries or build from source if the download fails. OpenSSL files will be installed to `~/android-openssl/android-ssl/`.

   To verify your OpenSSL setup:
   ```bash
   ./gradlew verifyOpenSsl
   ```

### Build Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/obscuraio/SlipNet.git
   cd SlipNet
   ```

2. **Initialize submodules**
   ```bash
   git submodule update --init --recursive
   ```

3. **Build the project**
   ```bash
   ./gradlew assembleDebug
   ```

   Or open the project in Android Studio and build from there.

## Project Structure

```
app/
├── src/main/
│   ├── java/app/slipnet/
│   │   ├── data/               # Data layer (repositories, database, native bridge)
│   │   │   ├── local/          # Room database and DataStore
│   │   │   ├── mapper/         # Entity mappers
│   │   │   ├── native/         # JNI bridge to Rust
│   │   │   └── repository/     # Repository implementations
│   │   ├── di/                 # Hilt dependency injection modules
│   │   ├── domain/             # Domain layer (models, use cases)
│   │   │   ├── model/          # Domain models
│   │   │   ├── repository/     # Repository interfaces
│   │   │   └── usecase/        # Business logic use cases
│   │   ├── presentation/       # UI layer (Compose screens)
│   │   │   ├── common/         # Shared UI components
│   │   │   ├── home/           # Home screen
│   │   │   ├── navigation/     # Navigation setup
│   │   │   ├── profiles/       # Profile management screens
│   │   │   ├── settings/       # Settings screen
│   │   │   └── theme/          # Material theme configuration
│   │   ├── service/            # Android services
│   │   │   ├── SlipNetVpnService.kt
│   │   │   ├── QuickSettingsTile.kt
│   │   │   └── BootReceiver.kt
│   │   └── tunnel/             # VPN tunnel implementation
│   └── rust/                   # Rust native library
│       └── slipstream-rust/    # QUIC/DNS tunneling implementation
├── build.gradle.kts
└── proguard-rules.pro
```

## Architecture

SlipNet follows Clean Architecture principles with three main layers:

- **Presentation Layer**: Jetpack Compose UI with ViewModels
- **Domain Layer**: Business logic and use cases
- **Data Layer**: Repositories, Room database, and native Rust bridge

### Tech Stack

- **UI**: Jetpack Compose, Material 3
- **Architecture**: MVVM, Clean Architecture
- **DI**: Hilt
- **Database**: Room
- **Preferences**: DataStore
- **Async**: Kotlin Coroutines & Flow
- **Native**: Rust via JNI (QUIC protocol implementation)
- **SSH**: JSch (mwiede fork with AES-GCM, ChaCha20 support)
- **HTTP**: OkHttp (HTTP/2 for DoH requests)

## Configuration

### Server Profile

Each server profile contains:

- **Name**: Display name for the profile
- **Tunnel Type**: DNSTT, Slipstream, SSH, DOH, or their SSH variants
- **Domain**: Server domain for DNS tunneling
- **Resolvers**: DNS resolver configurations

#### DNSTT-specific settings:
- **Public Key**: Server's Noise protocol public key (hex format)
- **DNS Transport**: UDP, DoT (DNS over TLS), or DoH (DNS over HTTPS)

#### Slipstream-specific settings:
- **Congestion Control**: QUIC congestion control algorithm (BBR, DCUBIC)
- **Keep-Alive Interval**: QUIC keep-alive interval in milliseconds
- **Authoritative Mode**: Use authoritative DNS resolution
- **GSO**: Generic Segmentation Offload for better performance

#### SSH settings (SSH, DNSTT+SSH, Slipstream+SSH):
- **SSH Host**: SSH server address
- **SSH Port**: SSH server port (default 22)
- **SSH Username/Password**: Authentication credentials
- **SSH Cipher**: Preferred encryption algorithm (AES-128-GCM, ChaCha20, AES-128-CTR)

#### DOH settings:
- **DoH Server URL**: HTTPS endpoint for DNS queries (e.g., `https://cloudflare-dns.com/dns-query`)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the GNU Affero General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [slipstream-rust](https://github.com/Mygod/slipstream-rust) - Rust QUIC tunneling library
- [Stream-Gate](https://github.com/free-mba/Stream-Gate) - DNS tunnel scanning method
