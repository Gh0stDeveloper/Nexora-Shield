#!/usr/bin/env bash
set -euo pipefail
guard_base="$1"
guard_tools="${BUILD_TOOLS:?BUILD_TOOLS must point to Android 35.0.0 build tools}"
function runtime_stage() {
  local runtime_operation="$1" runtime_destination="$2" runtime_diversity="$3"
  shift 3
  cargo run --locked --quiet -p nexora-shield-core --example stage_android_runtime -- \
    "$runtime_operation" "$guard_directory/baseline-unsigned.apk" "$runtime_destination" \
    "$guard_directory/root.key" dev.nexora.runtime o1-functional \
    'Ldev/nexora/runtime/Probe;#secret' 'Ldev/nexora/runtime/Probe;#sum' \
    'Ldev/nexora/runtime/Probe;#*Constant' 'Ldev/nexora/runtime/Probe;#constant' \
    --diversity-file "$runtime_diversity" --asset assets/secret-data.bin \
    --guard-key "$guard_directory/guard-signing.key" --signer-sha "$guard_directory/signer.sha256" --rasp "$guard_mode" "$@"
}
for guard_mode in report-only enforce; do
  guard_directory="$guard_base"
  if [[ "$guard_mode" == enforce ]]; then
    guard_directory="$guard_base-enforce"
    python - "$guard_base" "$guard_directory" <<'PY'
from pathlib import Path
import shutil,sys
source,target=map(Path,sys.argv[1:])
target.mkdir()
for name in ['baseline-unsigned.apk','root.key','guard-signing.key','ephemeral-test.p12','signer.sha256','signing-password.nshield-private','diversity.nshield-private']:
    shutil.copy2(source/name,target/name)
PY
    python scripts/testing/runtime_diversity.py unique "$guard_directory"
  fi
  for guard_candidate in original repeated unique; do
    guard_output="$guard_directory"
    guard_diversity="$guard_directory/diversity.nshield-private"
    if [[ "$guard_candidate" != original ]]; then
      guard_output="$guard_directory/$guard_candidate"
      mkdir "$guard_output"
    fi
    if [[ "$guard_candidate" == unique ]]; then guard_diversity="$guard_directory/unique.nshield-private"; fi
    runtime_stage prepare "$guard_output/runtime.nshield-private" "$guard_diversity"
    CARGO_TARGET_DIR=target/o1-android-runtime bash scripts/build-runtime-native.sh "$guard_output/runtime.nshield-private" "$guard_output/jniLibs"
    runtime_stage stage "$guard_output/runtime-unsigned.apk" "$guard_diversity" \
      --tools build/tools/smali --java "$(command -v java)" --native "$guard_output/jniLibs"
  done
  cargo build --locked --quiet -p nexora-shield-core --example inspect_runtime_vm
  python scripts/testing/runtime_diversity.py verify "$guard_directory" --inspector target/debug/examples/inspect_runtime_vm
  python scripts/testing/runtime-plan-test.py "$guard_directory" \
    --example target/debug/examples/stage_android_runtime --tools build/tools/smali --java "$(command -v java)"
  python scripts/testing/runtime-asset-plan-test.py "$guard_directory" \
    --example target/debug/examples/stage_android_runtime --tools build/tools/smali --java "$(command -v java)"
  python scripts/testing/runtime-diversity-plan-test.py "$guard_directory" --example target/debug/examples/stage_android_runtime
  cargo build --locked --quiet -p nexora-shield-core --example verify_runtime_guard
  python scripts/testing/qualify-runtime-apk.py "$guard_directory" --build-tools "$guard_tools"
  python scripts/testing/runtime-guard-host-test.py "$guard_directory" --verifier target/debug/examples/verify_runtime_guard
done
