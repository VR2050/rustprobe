#!/usr/bin/env bash
set -euo pipefail

PROFILE="debug"
SDK_DIR=""
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --sdk-dir)
      SDK_DIR="$2"
      shift 2
      ;;
    --output)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$SDK_DIR" ]]; then
  echo "Rust Android build requires --sdk-dir." >&2
  exit 1
fi

if [[ -z "$OUTPUT_DIR" ]]; then
  echo "Rust Android build requires --output." >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo was not found in PATH." >&2
  exit 1
fi

if ! cargo ndk --version >/dev/null 2>&1; then
  cat >&2 <<'EOF'
cargo-ndk is not installed.
Install it with:
  cargo install cargo-ndk
EOF
  exit 1
fi

if [[ ! -d "$SDK_DIR" ]]; then
  echo "Android SDK directory not found: $SDK_DIR" >&2
  exit 1
fi

find_latest_ndk() {
  local base="$1/ndk"
  if [[ ! -d "$base" ]]; then
    return 1
  fi

  find "$base" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1
}

NDK_DIR="${ANDROID_NDK_HOME:-}"
if [[ -z "$NDK_DIR" ]]; then
  if ! NDK_DIR="$(find_latest_ndk "$SDK_DIR")"; then
    cat >&2 <<EOF
Android NDK was not found under:
  $SDK_DIR/ndk

Install an NDK from Android Studio SDK Manager, or export ANDROID_NDK_HOME.
EOF
    exit 1
  fi
fi

export ANDROID_HOME="$SDK_DIR"
export ANDROID_SDK_ROOT="$SDK_DIR"
export ANDROID_NDK_HOME="$NDK_DIR"

mkdir -p "$OUTPUT_DIR"

PROFILE_FLAG=()
case "$PROFILE" in
  debug) ;;
  release) PROFILE_FLAG+=(--release) ;;
  *)
    echo "Unsupported profile: $PROFILE" >&2
    exit 1
    ;;
esac

echo "Building Rust JNI libraries"
echo "  SDK: $ANDROID_SDK_ROOT"
echo "  NDK: $ANDROID_NDK_HOME"
echo "  Output: $OUTPUT_DIR"
echo "  Profile: $PROFILE"

cargo ndk \
  -t armeabi-v7a \
  -t arm64-v8a \
  -o "$OUTPUT_DIR" \
  build \
  -p rustprobe-ffi \
  "${PROFILE_FLAG[@]}"
