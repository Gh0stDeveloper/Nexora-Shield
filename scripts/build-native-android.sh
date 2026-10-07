#!/usr/bin/env bash
set -euo pipefail

API_LEVEL="${NEXORA_ANDROID_API_LEVEL:-24}"
OUT_DIR="${1:-build/phase-f/jniLibs}"
NDK_ROOT="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"

if ! [[ "${API_LEVEL}" =~ ^[0-9]+$ ]] || (( API_LEVEL < 24 )); then
  echo "NEXORA_ANDROID_API_LEVEL must be an integer >= 24" >&2
  exit 2
fi

if [[ -z "${NDK_ROOT}" || ! -d "${NDK_ROOT}" ]]; then
  echo "ANDROID_NDK_HOME or ANDROID_NDK_ROOT must point to an Android NDK" >&2
  exit 2
fi

PREBUILT_ROOT="${NDK_ROOT}/toolchains/llvm/prebuilt"
TOOLCHAIN="$(find "${PREBUILT_ROOT}" -mindepth 1 -maxdepth 1 -type d -print -quit)"
if [[ -z "${TOOLCHAIN}" ]]; then
  echo "unable to locate the Android NDK LLVM toolchain under ${PREBUILT_ROOT}" >&2
  exit 2
fi

ARM64_LINKER="${TOOLCHAIN}/bin/aarch64-linux-android${API_LEVEL}-clang"
X64_LINKER="${TOOLCHAIN}/bin/x86_64-linux-android${API_LEVEL}-clang"
for linker in "${ARM64_LINKER}" "${X64_LINKER}"; do
  if [[ ! -x "${linker}" ]]; then
    echo "required Android linker is missing: ${linker}" >&2
    exit 2
  fi
done

rustup target add aarch64-linux-android x86_64-linux-android
mkdir -p "${OUT_DIR}/arm64-v8a" "${OUT_DIR}/x86_64"

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${ARM64_LINKER}"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="${X64_LINKER}"

cargo build --locked --release -p nexora-shield-native --target aarch64-linux-android
cargo build --locked --release -p nexora-shield-native --target x86_64-linux-android

cp target/aarch64-linux-android/release/libnexora_shield_native.so "${OUT_DIR}/arm64-v8a/libnexora_shield_native.so"
cp target/x86_64-linux-android/release/libnexora_shield_native.so "${OUT_DIR}/x86_64/libnexora_shield_native.so"

echo "Native Shield libraries written to ${OUT_DIR}"
