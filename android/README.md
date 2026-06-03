# Android Shell

This directory now contains:

- a minimal Android host app
- `VPNService` placeholders
- Gradle build scripts
- Rust JNI packaging hooks for APK builds

## APK build prerequisites

You need:

- Android SDK
- Android NDK installed under the SDK
- `cargo install cargo-ndk`
- Rust Android targets:
  - `rustup target add aarch64-linux-android`
  - `rustup target add armv7-linux-androideabi`

Copy `local.properties.example` to `local.properties` and set `sdk.dir`.

## Build flow

Gradle runs `scripts/build-rust-android.sh` before `preBuild`.

That script:

- locates the Android SDK and NDK
- calls `cargo ndk`
- builds `rustprobe-ffi`
- writes `.so` files into `app/src/main/jniLibs`

## Example commands

From `android/`:

- `./gradlew assembleDebug`
- `./gradlew assembleRelease -Prust.android.profile=release`

## Current limitation

This project now has an APK packaging path, but it still needs real device validation for:

- `VPNService`
- TUN traffic capture
- owner UID resolution
- per-flow app attribution
