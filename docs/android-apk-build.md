# Android APK Build

This document describes the current Rust-to-APK packaging path.

## 1. Rust native library

The Android app loads `librustprobe_ffi.so` via `RustBridge`.

The Rust crate responsible for packaging is:

- `crates/rustprobe-ffi`

It is configured as:

- `crate-type = ["cdylib", "rlib"]`

## 2. Packaging approach

The current project uses prebuilt JNI libraries placed in:

- `android/app/src/main/jniLibs/<abi>/`

This follows the Android packaging model for prebuilt native libraries documented by Android Developers:

- Android prebuilt native libraries in `jniLibs`: https://developer.android.com/studio/projects/gradle-external-native-builds

## 3. Rust build tool

The current build chain uses `cargo-ndk` to cross-compile Rust for Android ABIs.

Reference:

- `cargo-ndk` project: https://github.com/bbqsrc/cargo-ndk

## 4. Supported ABIs

Current Gradle ABI filters and Rust build targets:

- `arm64-v8a`
- `armeabi-v7a`

ABI naming reference:

- Android NDK ABI guide: https://developer.android.com/ndk/guides/abis.html

## 5. Build steps

1. Install Android SDK and Android NDK.
2. Install `cargo-ndk`.
3. Add Rust Android targets with `rustup`.
4. Set `sdk.dir` in `android/local.properties`.
5. Run `./gradlew assembleDebug` from `android/`.

Gradle will invoke:

- `android/scripts/build-rust-android.sh`

That script:

- resolves SDK and NDK paths
- exports Android build env vars
- runs `cargo ndk`
- writes output `.so` files into `app/src/main/jniLibs`

## 6. Current validation status

The repository now contains the packaging path, but this environment has not yet validated:

- installed SDK/NDK presence
- `cargo-ndk` availability
- successful `.so` generation on this machine
- final APK install on a device

Those are the next device-facing validation steps.
