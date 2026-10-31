#!/usr/bin/env bash
set -euo pipefail
runtime_sdk="${SDK_ROOT:?SDK_ROOT required}"
runtime_log="build/o1-runtime/emulator.log"
runtime_avd="nexora_o1_runtime"
export ANDROID_AVD_HOME="$HOME/.android/avd"
mkdir -p "$ANDROID_AVD_HOME"
runtime_manager="$runtime_sdk/cmdline-tools/latest/bin/sdkmanager"
runtime_emulator="$runtime_sdk/emulator/emulator"
runtime_adb="$runtime_sdk/platform-tools/adb"
runtime_image="system-images;android-35;aosp_atd;x86_64"
test -e /dev/kvm
sudo chmod 666 /dev/kvm
timeout 600 "$runtime_manager" "emulator" "$runtime_image"
"$runtime_emulator" -accel-check
echo no | "$runtime_sdk/cmdline-tools/latest/bin/avdmanager" create avd --force --name "$runtime_avd" --package "$runtime_image" --device pixel_6
nohup "$runtime_emulator" -avd "$runtime_avd" -no-window -noaudio -no-boot-anim -no-snapshot -no-metrics -gpu swiftshader_indirect -accel on -cores 2 -memory 2048 -camera-back none -camera-front none > "$runtime_log" 2>&1 &
runtime_pid=$!
for runtime_attempt in {1..120}; do
  if ! kill -0 "$runtime_pid" 2>/dev/null; then
    tail -n 80 "$runtime_log" >&2
    exit 1
  fi
  runtime_boot="$("$runtime_adb" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
  if [[ "$runtime_boot" == 1 ]]; then
    echo 'Android runtime qualification device booted'
    exit 0
  fi
  sleep 2
done
echo 'Android runtime qualification requires a booted device' >&2
tail -n 80 "$runtime_log" >&2
exit 1
