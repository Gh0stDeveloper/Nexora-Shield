#!/usr/bin/env python3
"""Install/launch exact signed APKs; never infer runtime success from packaging."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

p=argparse.ArgumentParser()
p.add_argument('directory',type=Path)
p.add_argument('--adb',required=True)
args=p.parse_args()
def adb(*values,check=True):
    return subprocess.run([args.adb,*values],check=check,capture_output=True,text=True,timeout=120).stdout
root=args.directory
evidence=json.loads((root/'evidence.json').read_text())
results={}
for name,expected in [('baseline','NEXORA_RUNTIME_OK'),('runtime','NEXORA_RUNTIME_OK'),('tampered','NEXORA_RUNTIME_REJECTED')]:
    apk=root/f'{name}.apk'
    if hashlib.sha256(apk.read_bytes()).hexdigest()!=evidence['artifacts'][name]: raise SystemExit('APK changed after final verification')
    adb('shell','am','force-stop','dev.nexora.runtime',check=False)
    adb('install','-r',str(apk))
    installed=adb('shell','pm','path','dev.nexora.runtime').strip()
    if not installed.startswith('package:') or '\n' in installed: raise SystemExit('Unexpected installed APK identity')
    pulled=root/f'{name}-installed.apk'
    adb('pull',installed.removeprefix('package:'),str(pulled))
    if hashlib.sha256(pulled.read_bytes()).hexdigest()!=evidence['artifacts'][name]: raise SystemExit('Installed APK hash differs from verified final APK')
    adb('logcat','-c')
    adb('shell','am','start','-W','-n','dev.nexora.runtime/.MainActivity')
    for _ in range(40):
        log=adb('logcat','-d','-s','NexoraRuntime:I','*:S')
        if expected in log: break
        if 'NEXORA_RUNTIME_' in log: raise SystemExit('Android runtime returned the wrong functional outcome')
        time.sleep(0.5)
    else: raise SystemExit('Android runtime execution evidence timed out')
    results[name]={'installed_sha256':evidence['artifacts'][name],'result':expected}
evidence['android_execution']='passed'
evidence['device']={'sdk':adb('shell','getprop','ro.build.version.sdk').strip(),'abi':adb('shell','getprop','ro.product.cpu.abi').strip(),'fingerprint':adb('shell','getprop','ro.build.fingerprint').strip()}
evidence['execution_results']=results
(root/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
print('ANDROID_RUNTIME_OK: baseline/protected equivalence and authenticated native tamper refusal')
