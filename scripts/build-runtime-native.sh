#!/usr/bin/env bash
set -euo pipefail
runtime_config="$(realpath "$1")"
runtime_output="$2"
runtime_ndk="${ANDROID_NDK_HOME:?ANDROID_NDK_HOME must point to pinned Android NDK}"
runtime_toolchain="$runtime_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
grep -Eq '^Pkg.Revision *= *27\.3\.13750724$' "$runtime_ndk/source.properties"
test -f "$runtime_config"
mkdir -p "$runtime_output/arm64-v8a" "$runtime_output/x86_64"
export NEXORA_RUNTIME_IMAGE="$runtime_config"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$runtime_toolchain/aarch64-linux-android24-clang"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$runtime_toolchain/x86_64-linux-android24-clang"
rustup target add aarch64-linux-android x86_64-linux-android
for runtime_pair in 'aarch64-linux-android arm64-v8a' 'x86_64-linux-android x86_64'; do
  read -r runtime_target runtime_abi <<< "$runtime_pair"
  cargo build --locked --release -p nexora-shield-native --features android-runtime --target "$runtime_target"
  cp "${CARGO_TARGET_DIR:-target}/$runtime_target/release/libnexora_shield_native.so" "$runtime_output/$runtime_abi/"
done
echo 'Build-bound Android runtime libraries created (configuration remains private)'
