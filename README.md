# SlipNet

A modern Android VPN client built with Jetpack Compose and Kotlin, featuring DNS-over-QUIC tunneling powered by a Rust backend.

## Features

- **Modern UI**: Built entirely with Jetpack Compose and Material 3 design
- **DNS-over-QUIC**: Secure DNS tunneling using the QUIC protocol
- **Multiple Profiles**: Create and manage multiple server configurations
- **Quick Settings Tile**: Toggle VPN connection directly from the notification shade
- **Auto-connect on Boot**: Optionally reconnect VPN when device starts
- **Dark Mode**: Full support for system-wide dark theme

## Server Setup

To use this client, you need a compatible server. Please set up your server using the **socks mode** of the following deployment script:

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

## Configuration

### Server Profile

Each server profile contains:

- **Name**: Display name for the profile
- **Domain**: Server domain for DNS tunneling
- **Resolvers**: List of DNS resolver configurations
- **Congestion Control**: QUIC congestion control algorithm (cubic, reno, bbr)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [slipstream-rust](https://github.com/Mygod/slipstream-rust) - Rust QUIC tunneling library
- [Stream-Gate](https://github.com/free-mba/Stream-Gate) - DNS tunnel scanning method
