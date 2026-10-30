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
runtime_image_sha="$(python - "$runtime_config" <<'PY'
import hashlib,sys
from pathlib import Path
path=Path(sys.argv[1]);metadata=path.stat()
if metadata.st_size>32*1024*1024 or metadata.st_mode&0o077:
    raise SystemExit('Runtime configuration must be bounded and private')
with path.open('rb') as source:configuration=source.read(32*1024*1024+1)
if len(configuration)>32*1024*1024:raise SystemExit('Runtime configuration exceeds its read budget')
print(hashlib.sha256(configuration).hexdigest())
PY
)"
runtime_cache="${CARGO_TARGET_DIR:-target}/runtime-images/$runtime_image_sha"
rustup target add aarch64-linux-android x86_64-linux-android
for runtime_pair in 'aarch64-linux-android arm64-v8a' 'x86_64-linux-android x86_64'; do
  read -r runtime_target runtime_abi <<< "$runtime_pair"
  export CARGO_TARGET_DIR="$runtime_cache/$runtime_target"
  cargo build --locked --release -p nexora-shield-native --features android-runtime --target "$runtime_target"
  python - "$runtime_config" "$CARGO_TARGET_DIR/$runtime_target/release/libnexora_shield_native.so" "$runtime_abi" "$runtime_image_sha" <<'PY'
import hashlib,json,sys,struct
from pathlib import Path
with Path(sys.argv[1]).open('rb') as source:configuration=source.read(32*1024*1024+1)
if len(configuration)>32*1024*1024 or hashlib.sha256(configuration).hexdigest()!=sys.argv[4]:
    raise SystemExit('Private runtime configuration changed during native compilation')
image=json.loads(configuration)
fingerprint=hashlib.sha256(json.dumps([image['schema'],image['application_id'],image['build_id'],image['entries'],image.get('guard_key'),image.get('guard_binding')],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
binary=Path(sys.argv[2]).read_bytes()
machine={'arm64-v8a':183,'x86_64':62}[sys.argv[3]]
if binary[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',binary,18)[0]!=machine or binary.count(('NEXORA_RUNTIME_V1:'+fingerprint).encode())!=1:
    raise SystemExit('Compiled Android library does not match its ABI and frozen private runtime image')
PY
  cp "${CARGO_TARGET_DIR:-target}/$runtime_target/release/libnexora_shield_native.so" "$runtime_output/$runtime_abi/"
done
echo 'Build-bound Android runtime libraries created (configuration remains private)'
