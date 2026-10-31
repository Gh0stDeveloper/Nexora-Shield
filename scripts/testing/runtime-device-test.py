#!/usr/bin/env python3
"""Install and launch exact signed APKs, requiring real runtime security outcomes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument('directory', type=Path)
p.add_argument('--adb', required=True)
args = p.parse_args()

def adb(*values, check=True):
    result=subprocess.run([args.adb, *values], capture_output=True, text=True, timeout=120)
    if check and result.returncode:
        raise SystemExit(f'ADB {values[0]} failed: {result.stderr.strip()} {result.stdout.strip()}')
    return result.stdout

root = args.directory
evidence = json.loads((root/'evidence.json').read_text())
results = {}
guarded = evidence.get('guard_selected', False)
if 'engine_report_sha256' in evidence:
    report_path=root/'engine-report.json'
    if hashlib.sha256(report_path.read_bytes()).hexdigest()!=evidence['engine_report_sha256']:raise SystemExit('Integrated engine report changed before Android execution')
    report=json.loads(report_path.read_text())
    required={'baseline','runtime','native-tampered','provider-removed'} if evidence['entrypoint']=='cli' else {'runtime'}
    if set(evidence['artifacts'])!=required or not guarded or report!=evidence['engine_report']:raise SystemExit('Incomplete integrated engine device matrix')
    if report['output_sha256']!=evidence['artifacts']['runtime'] or report['production_protected'] is not False or not evidence['retrace_final_apk_verified']:raise SystemExit('Integrated proof is not bound to final experimental APK')
if 'diversity' in evidence:
    required={'baseline','runtime','tampered','guard-signature','guard-missing','resource-tampered','encrypted-asset-tampered','dex-tampered','native-tampered','provider-removed','extra-entry','foreign-native','resigned','diversified'}
    if set(evidence['artifacts'])!=required or not guarded:raise SystemExit('Incomplete guarded diversity APK matrix')
    proof=evidence['diversity']
    if not all(proof.get(k) is True for k in ['runtime_image_reproduced','native_libraries_reproduced','rebuilt_apk_reproduced','signed_apk_reproduced','private_inputs_absent','vm_cfg_materialized','vm_opcode_map_varied','final_native_payloads_verified']):raise SystemExit('Incomplete final-payload diversity/reproduction proof')
    if proof['signed_apk_sha256']!=evidence['artifacts']['runtime'] or proof['unique_signed_apk_sha256']!=evidence['artifacts']['diversified']:raise SystemExit('Diversity proof is not bound to installed APK hashes')
adb('uninstall', 'dev.nexora.runtime', check=False)
for name, expected_hash in evidence['artifacts'].items():
    print(f'Android runtime case: {name}', flush=True)
    positive = name in ('baseline', 'runtime','diversified')
    expected = 'NEXORA_RUNTIME_OK' if positive else (
        'NEXORA_GUARD_REJECTED' if guarded and name != 'provider-removed' else 'NEXORA_RUNTIME_REJECTED')
    apk = root/f'{name}.apk'
    if hashlib.sha256(apk.read_bytes()).hexdigest() != expected_hash:
        raise SystemExit('APK changed after final verification')
    adb('shell', 'am', 'force-stop', 'dev.nexora.runtime', check=False)
    # Rejected startup can leave ActivityManager retry state. Each adversarial
    # APK gets a separate installation; upgrade behavior belongs to the O.2 matrix.
    # Frontend matrices can start with runtime directly, without a baseline case.
    if results:
        adb('uninstall', 'dev.nexora.runtime')
    install=adb('install', str(apk))
    if 'Success' not in install.splitlines():
        raise SystemExit(f'Android did not confirm installation: {name}')
    installed = adb('shell', 'pm', 'path', 'dev.nexora.runtime').strip()
    if not installed.startswith('package:') or '\n' in installed:
        raise SystemExit('Unexpected installed APK identity')
    pulled = root/f'{name}-installed.apk'
    adb('pull', installed.removeprefix('package:'), str(pulled))
    if adb('shell','pm','path','dev.nexora.runtime').strip()!=installed:
        raise SystemExit(f'Installed package path changed during verification: {name}')
    if hashlib.sha256(pulled.read_bytes()).hexdigest() != expected_hash:
        raise SystemExit('Installed APK hash differs from verified final APK')
    adb('logcat', '-c')
    # A deliberately rejected startup never completes ActivityManager's -W wait.
    # The functional/security marker below remains mandatory for every case.
    adb('shell', 'am', 'start', '-n', 'dev.nexora.runtime/.MainActivity', check=positive)
    for _ in range(40):
        log = adb('logcat', '-d', '-s', 'NexoraRuntime:I', 'NexoraGuard:I', '*:S')
        if 'UNEXPECTED_FAILURE' in log:
            raise SystemExit(f'Unrelated Android runtime failure: {name}')
        if expected in log:
            break
        if 'NEXORA_RUNTIME_OK' in log or 'NEXORA_RUNTIME_REJECTED' in log or 'NEXORA_GUARD_REJECTED' in log:
            raise SystemExit(f'Android returned the wrong security outcome: {name}')
        time.sleep(0.5)
    else:
        raise SystemExit(f'Android execution evidence timed out: {name}')
    results[name] = {'installed_sha256': expected_hash, 'result': expected}
    if name in ['runtime','diversified'] and guarded:
        match = re.search(r'NEXORA_GUARD_STATUS=(\d+)', log)
        if match is None:
            raise SystemExit('Protected app did not execute its startup guard')
        status = int(match.group(1))
        if not status & (1 << 25):
            raise SystemExit('Installed app did not verify its integrity graph')
        if bool(status & (1 << 24)) != (evidence['rasp_mode'] == 'report_only'):
            raise SystemExit('Installed RASP policy differs from selected mode')
        if status & 0xffff == 0:
            raise SystemExit('Emulator RASP observation was not collected')
        evidence['rasp_runtime' if name=='runtime' else 'diversified_rasp_runtime'] = {'mode': evidence['rasp_mode'],
            'signals_evaluated': status & 0xffff, 'risk_level': (status >> 16) & 0xff,
            'normal_execution_allowed': True}
evidence['android_execution'] = 'passed'
if 'diversity' in evidence:evidence['diversity']['android_execution']='passed'
evidence['device'] = {
    'sdk': adb('shell', 'getprop', 'ro.build.version.sdk').strip(),
    'abi': adb('shell', 'getprop', 'ro.product.cpu.abi').strip(),
    'fingerprint': adb('shell', 'getprop', 'ro.build.fingerprint').strip()}
evidence['execution_results'] = results
(root/'evidence.json').write_text(json.dumps(evidence, indent=2)+'\n')
print(f'ANDROID_RUNTIME_OK: exact installed artifacts={len(results)}, guarded={guarded}')
