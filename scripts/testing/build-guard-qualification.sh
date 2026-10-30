#!/usr/bin/env bash
set -euo pipefail
guard_base="$1"
guard_tools="${BUILD_TOOLS:?BUILD_TOOLS must point to Android 35.0.0 build tools}"
for guard_mode in report-only enforce; do
  guard_directory="$guard_base"
  if [[ "$guard_mode" == enforce ]]; then
    guard_directory="$guard_base-enforce"
    python - "$guard_base" "$guard_directory" <<'PY'
from pathlib import Path
import shutil,sys
source,target=map(Path,sys.argv[1:])
target.mkdir()
for name in ['baseline-unsigned.apk','root.key','guard-signing.key','ephemeral-test.p12','signer.sha256','signing-password.nshield-private']:
    shutil.copy2(source/name,target/name)
PY
  fi
  cargo run --locked --quiet -p nexora-shield-core --example stage_android_runtime -- \
    prepare "$guard_directory/baseline-unsigned.apk" "$guard_directory/runtime.nshield-private" \
    "$guard_directory/root.key" dev.nexora.runtime o1-functional \
    'Ldev/nexora/runtime/Probe;#secret' 'Ldev/nexora/runtime/Probe;#sum' \
    --guard-key "$guard_directory/guard-signing.key" --signer-sha "$guard_directory/signer.sha256" --rasp "$guard_mode"
  CARGO_TARGET_DIR=target/o1-android-runtime bash scripts/build-runtime-native.sh "$guard_directory/runtime.nshield-private" "$guard_directory/jniLibs"
  cargo run --locked --quiet -p nexora-shield-core --example stage_android_runtime -- \
    stage "$guard_directory/baseline-unsigned.apk" "$guard_directory/runtime-unsigned.apk" \
    "$guard_directory/root.key" dev.nexora.runtime o1-functional \
    'Ldev/nexora/runtime/Probe;#secret' 'Ldev/nexora/runtime/Probe;#sum' \
    --guard-key "$guard_directory/guard-signing.key" --signer-sha "$guard_directory/signer.sha256" --rasp "$guard_mode" \
    --tools build/tools/smali --java "$(command -v java)" --native "$guard_directory/jniLibs"
  python scripts/testing/runtime-plan-test.py "$guard_directory" \
    --example target/debug/examples/stage_android_runtime --tools build/tools/smali --java "$(command -v java)"
  cargo build --locked --quiet -p nexora-shield-core --example verify_runtime_guard
  python scripts/testing/qualify-runtime-apk.py "$guard_directory" --build-tools "$guard_tools"
  python scripts/testing/runtime-guard-host-test.py "$guard_directory" --verifier target/debug/examples/verify_runtime_guard
done
