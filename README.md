# SlipNet

> **SlipNet is NOT available on any app store.** Any version you find on Google Play, the Apple App Store, or any other marketplace is **not published by us** and may be outdated, modified, or unsafe. The only official sources are this GitHub repository and our [Telegram channel](https://t.me/SlipNet_app).

<p align="center">
  <img src="imgs/icon.png" alt="SlipNet Logo" width="200">
</p>

A fast, modern VPN client featuring DNS tunneling with support for multiple protocols. Available as an Android app (Jetpack Compose + Kotlin) and a cross-platform CLI client (Go).

> **This is a legitimate open-source anti-censorship tool** designed to help users in countries with internet censorship access the free internet. It is comparable to [Tor](https://www.torproject.org/), [Psiphon](https://psiphon.ca/), [Outline VPN](https://getoutline.org/) (Google Jigsaw), and [dnstt](https://www.bamsoftware.com/software/dnstt/). This project does not target, exploit, or attack any systems — it is a client-side privacy tool used voluntarily by end users.

## Desktop GUI (Mac, Windows, Linux)

**Prefer a point-and-click interface?** [**SlipStreamGUI**](https://github.com/mirzaaghazadeh/SlipStreamGUI) is a modern, cross-platform GUI client — no terminal required. It uses this project's binaries (SlipNet CLI) under the hood. Download, install, and connect with a few clicks.

[![SlipStreamGUI](https://img.shields.io/badge/Download-SlipStreamGUI-green?style=for-the-badge)](https://github.com/mirzaaghazadeh/SlipStreamGUI/releases/latest)

## Community

Join our Telegram channel for updates, support, and discussions:

[![Telegram](https://img.shields.io/badge/Telegram-@SlipNet__app-blue?logo=telegram)](https://t.me/SlipNet_app)

## Donate

If you want to support development:

- **USDT (BEP-20)**: ``

## Tunnel Types

SlipNet supports multiple tunnel types with optional SSH chaining:

| Tunnel Type | Protocol | Description |
|-------------|----------|-------------|
| **DNSTT** | KCP + Noise | Stable and reliable DNS tunneling |
| **DNSTT + SSH** | KCP + Noise + SSH | DNSTT with SSH chaining for zero DNS leaks |
| **NoizDNS** | KCP + Noise | DPI-resistant DNS tunneling |
| **NoizDNS + SSH** | KCP + Noise + SSH | NoizDNS with SSH chaining |
| **Slipstream** | QUIC | High-performance QUIC tunneling |
| **Slipstream + SSH** | QUIC + SSH | Slipstream with SSH chaining |
| **SSH** | SSH | Standalone SSH tunnel (no DNS tunneling) |
| **NaiveProxy** | HTTPS (Chromium) | HTTPS tunnel with authentic Chrome TLS fingerprinting |
| **NaiveProxy + SSH** | HTTPS + SSH | NaiveProxy with SSH chaining for extra encryption |
| **DOH** | DNS over HTTPS | DNS-only encryption via HTTPS (RFC 8484) |
| **Tor** | Tor Network | Connect via Tor with Snowflake, obfs4, Meek, or custom bridges |

**Note:** DNSTT is the default and recommended tunnel type for most users. NoizDNS adds DPI resistance on top of DNSTT for censored networks. SSH variants add an extra layer of encryption and can prevent DNS leaks.

## Features

- **Modern UI**: Built entirely with Jetpack Compose and Material 3 design
- **Multiple Tunnel Types**: DNSTT, NoizDNS, Slipstream, SSH, NaiveProxy, DOH, and Tor with optional SSH chaining
- **NoizDNS**: DPI-resistant DNS tunneling with optional stealth mode
- **SSH Tunneling**: Chain SSH through DNSTT, NoizDNS, Slipstream, or NaiveProxy, or use standalone SSH
- **NaiveProxy**: Chromium-based HTTPS tunnel with authentic TLS fingerprinting to evade DPI
- **DNS over HTTPS**: Encrypt DNS queries via HTTPS without tunneling other traffic
- **DNS Transport Selection**: Choose UDP, DoT, or DoH for DNSTT DNS resolution
- **SSH Cipher Selection**: Choose between AES-128-GCM, ChaCha20, and AES-128-CTR
- **DNS Server Scanning**: Automatically discover and test compatible DNS servers with EDNS probing, NXDOMAIN hijacking detection, and country-based IP range scanning
- **Multiple Profiles**: Create and manage multiple server configurations
- **Configurable Proxy**: Set custom listen address and port
- **Quick Settings Tile**: Toggle VPN connection directly from the notification shade
- **Auto-connect on Boot**: Optionally reconnect VPN when device starts
- **APK Sharing**: Share the app via Bluetooth or other methods in case of internet shutdowns
- **Debug Logging**: Toggle detailed traffic logs for troubleshooting
- **Dark Mode**: Full support for system-wide dark theme

## Server Setup

To use this client, you must have a compatible server. Please configure your server using one of the following deployment scripts:

**NoizDNS (recommended for censored networks):**
[**noizdns-deploy**](https://github.com/anonvector/noizdns-deploy) — One-click NoizDNS server with interactive management menu. Auto-detects both DNSTT and NoizDNS clients.

**DNSTT + Slipstream (combined):**
[**dnstm**](https://github.com/net2share/dnstm) — DNS Tunnel Manager supporting both Slipstream and DNSTT with SOCKS5, SSH, and Shadowsocks backends

**DNSTT**:
[**dnstt-deploy**](https://github.com/bugfloyd/dnstt-deploy)

**Slipstream:**
[**slipstream-rust-deploy**](https://github.com/AliRezaBeigy/slipstream-rust-deploy)

**NaiveProxy:**
[**slipgate**](https://github.com/anonvector/slipgate)

## Screenshots

<p align="center">
  <img src="imgs/screenshot_1.jpg" alt="Home Screen" width="250">
  &nbsp;&nbsp;
  <img src="imgs/screenshot_2.jpg" alt="Tunnel Types" width="250">
  &nbsp;&nbsp;
  <img src="imgs/screenshot_3.jpg" alt="Settings" width="250">
</p>

## Requirements

### Android App
- Android 7.0 (API 24) or higher
- Android Studio Hedgehog (2023.1.1) or later
- JDK 17
- Rust toolchain (for building the native library)
- Android NDK 29

### CLI Client
- Go 1.24+ (auto-downloaded via GOTOOLCHAIN if needed)
- No other dependencies (statically linked binaries)

## Building (Android)

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
   git clone https://github.com/anonvector/SlipNet.git
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

## CLI Client

SlipNet includes a cross-platform CLI client for **macOS**, **Linux**, and **Windows**. It connects using a `slipnet://` config URI and starts a local SOCKS5 proxy. For a GUI alternative, see [SlipStreamGUI](https://github.com/mirzaaghazadeh/SlipStreamGUI).

### Download

Pre-built binaries are available on the Releases page:

| Platform | Binary |
|----------|--------|
| macOS (Apple Silicon) | `slipnet-darwin-arm64` |
| macOS (Intel) | `slipnet-darwin-amd64` |
| Linux (x64) | `slipnet-linux-amd64` |
| Linux (ARM64) | `slipnet-linux-arm64` |
| Windows (x64) | `slipnet-windows-amd64.exe` |

### CLI Usage

```bash
# Basic usage — auto-detects server if DNS delegation isn't set up
./slipnet 'slipnet://BASE64...'

# Specify a custom DNS resolver
./slipnet --dns 1.1.1.1 'slipnet://BASE64...'

# Use a custom local proxy port
./slipnet --port 9050 'slipnet://BASE64...'

# Show version
./slipnet --version
```

Once connected, configure your apps to use the SOCKS5 proxy:

```bash
# Test with curl
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me

# If the server requires SOCKS5 authentication (username:password)
curl --socks5-hostname user:pass@127.0.0.1:1080 https://ifconfig.me

# Firefox: Settings → Network → SOCKS5 proxy: 127.0.0.1:1080
#          Check "Proxy DNS when using SOCKS v5"

# Chrome (launch with proxy flag):
google-chrome --proxy-server="socks5://127.0.0.1:1080"
```

The CLI auto-detects when DNS delegation isn't available and falls back to connecting directly to the server via its NS record.

### Building CLI from Source

```bash
git clone https://github.com/anonvector/SlipNet.git
cd SlipNet
git submodule update --init --recursive
cd cli
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o slipnet .
```

Cross-compile for other platforms:

```bash
# Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o slipnet-linux-amd64 .

# Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o slipnet-windows-amd64.exe .

# macOS Intel
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o slipnet-darwin-amd64 .
```

## Project Structure

```
cli/                        # Cross-platform CLI client (Go)
├── main.go                 # URI parser, tunnel client, SOCKS5 proxy
├── go.mod
└── go.sum
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
- **Tunnel Type**: DNSTT, NoizDNS, Slipstream, SSH, NaiveProxy, DOH, Tor, or their SSH variants
- **Domain**: Server domain for DNS tunneling
- **Resolvers**: DNS resolver configurations

#### DNSTT / NoizDNS settings:
- **Public Key**: Server's Noise protocol public key (hex format)
- **DNS Transport**: UDP, TCP, DoT (DNS over TLS), or DoH (DNS over HTTPS)
- **Stealth Mode** (NoizDNS only): Trades speed for harder DPI detection

#### Slipstream-specific settings:
- **Congestion Control**: QUIC congestion control algorithm (BBR, DCUBIC)
- **Keep-Alive Interval**: QUIC keep-alive interval in milliseconds
- **Authoritative Mode**: Use authoritative DNS resolution
- **GSO**: Generic Segmentation Offload for better performance

#### NaiveProxy settings (NaiveProxy, NaiveProxy+SSH):
- **Server Port**: Caddy server port (default 443)
- **Proxy Username**: HTTP proxy authentication username
- **Proxy Password**: HTTP proxy authentication password

#### SSH settings (SSH, DNSTT+SSH, NoizDNS+SSH, Slipstream+SSH, NaiveProxy+SSH):
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
   
## License & Usage

This project is released under the **SlipNet Source-Available License**.

**You are allowed to:**
- View, study, and modify the source code for **personal, private use**
- Use the software locally for educational or research purposes
- Fork the repository to submit contributions (Pull Requests) to the original project

**You are NOT allowed to:**
- **Distribute** this software (source or binary) to third parties
- **Publish** this application on app stores (including Google Play, F-Droid, or Apple App Store)
- **Commercialize** the software or any derivative works

See [LICENSE](./LICENSE) for the full legal terms.

## Name & Branding Notice

**"SlipNet"** is the reserved project name.

Use of the project name, logo, or branding in derivative works or republished versions is **strictly prohibited** without explicit written permission from the maintainers. This applies even if you have modified or forked the code.

## Distribution Notice

This project is **not authorized** for distribution on any application store, marketplace, or file-hosting service.

**If you find this application on Google Play, the Apple App Store, or any other marketplace, it is an UNAUTHORIZED build.** It may be outdated, modified, or malicious. Please download SlipNet only from the official repository.


## Acknowledgments

- [slipstream-rust](https://github.com/Mygod/slipstream-rust) - Rust QUIC tunneling library
- [Stream-Gate](https://github.com/free-mba/Stream-Gate) - DNS tunnel scanning method
