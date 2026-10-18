#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SRC="$ROOT/build/source"
PATCH="$ROOT/patches/android-capi.patch"
[[ -f "$SRC/Cargo.toml" ]] || { echo 'Run scripts/bootstrap.py first' >&2; exit 1; }
(cd "$SRC" && patch --forward --batch -p1 < "$PATCH")
LOCK_SHA="$(sha256sum "$SRC/Cargo.lock" | cut -d' ' -f1)"
EXPECTED="$(python3 -c 'import json; print(json.load(open("pins.json"))["upstream"]["cargo_lock_sha256"])')"
[[ "$LOCK_SHA" == "$EXPECTED" ]] || { echo 'Cargo.lock pin mismatch' >&2; exit 1; }
NDK="${ANDROID_NDK_HOME:-$ROOT/build/ndk}"
TOOL="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
[[ -x "$TOOL/clang" && -x "$TOOL/llvm-readelf" ]] || { echo 'NDK toolchain unavailable' >&2; exit 1; }
export CC_aarch64_linux_android="$TOOL/aarch64-linux-android24-clang"
export CXX_aarch64_linux_android="$TOOL/aarch64-linux-android24-clang++"
export AR_aarch64_linux_android="$TOOL/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
export CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_PROFILE_RELEASE_STRIP=symbols
export CARGO_PROFILE_RELEASE_OPT_LEVEL=1 CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=2
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" CARGO_TARGET_DIR="$ROOT/build/target"
export RUSTFLAGS="-C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-soname,libyara_x_capi.so --remap-path-prefix=$SRC=/src --remap-path-prefix=$CARGO_HOME=/cargo --remap-path-prefix=$ROOT/build/target=/target --remap-path-prefix=$ROOT=/workspace"
RUST_VERSION="$(python3 -c 'import json; print(json.load(open("pins.json"))["rust"]["version"])')"
python3 scripts/run-bounded.py cargo "+$RUST_VERSION" build --manifest-path "$SRC/Cargo.toml" --locked -p yara-x-capi --release --target aarch64-linux-android --no-default-features --features capi
mkdir -p dist
cp "$CARGO_TARGET_DIR/aarch64-linux-android/release/libyara_x_capi.so" dist/libyara_x_capi.so
cp "$SRC/capi/include/yara_x.h" dist/yara_x.h
python3 scripts/metadata.py
python3 scripts/verify.py
