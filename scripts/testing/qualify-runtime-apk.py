#!/usr/bin/env python3
"""Align/sign runtime fixtures and bind evidence to delivered APK bytes."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import zipfile

p=argparse.ArgumentParser()
p.add_argument('directory',type=Path)
p.add_argument('--build-tools',type=Path,required=True)
p.add_argument('--keytool',default='keytool')
args=p.parse_args()
root=args.directory
tools=args.build_tools
image=json.loads((root/'runtime.nshield-private').read_text())
baseline=root/'baseline-unsigned.apk'
staged=root/'runtime-unsigned.apk'
probe='Nexora_🔒_runtime_فارسی'
units=probe.encode('utf-16-be')
cesu=''.join(chr(int.from_bytes(units[i:i+2],'big')) for i in range(0,len(units),2)).encode('utf-8','surrogatepass')
with zipfile.ZipFile(baseline) as z:
    if cesu not in z.read('classes.dex'): raise SystemExit('Baseline exposure probe is missing')
    if not z.read('assets/secret-data.bin').startswith(b'Nexora private asset v1\x00\xff'): raise SystemExit('Baseline asset exposure probe is missing')
    constant_probes=[bytes.fromhex('1400df9b5713'), struct.pack('<Q',0x123456789abcdef)]
    original_dex=b''.join(z.read(n) for n in z.namelist() if n.endswith('.dex'))
    if any(value not in original_dex for value in constant_probes): raise SystemExit('Baseline constant exposure probe is missing')
with zipfile.ZipFile(staged) as z:
    names=set(z.namelist())
    if not {'classes.dex','classes2.dex','lib/arm64-v8a/libnexora_shield_native.so','lib/x86_64/libnexora_shield_native.so'}<=names: raise SystemExit('Runtime APK inventory is incomplete')
    root_key=(root/'root.key').read_bytes()
    for name in z.namelist():
        data=z.read(name)
        if probe.encode() in data or cesu in data or b'Nexora private asset v1\x00\xff' in data or root_key in data or ((root/'guard-signing.key').exists() and (root/'guard-signing.key').read_bytes() in data): raise SystemExit('Final runtime APK exposes protected fixture material')
        if name.endswith('.dex') and any(value in data for value in constant_probes): raise SystemExit('Final DEX still exposes selected fixture constants')
        if name.endswith(('.key','.p12','.nshield-private')): raise SystemExit('Private build file entered APK')
    binaries={abi:hashlib.sha256(z.read(f'lib/{abi}/libnexora_shield_native.so')).hexdigest() for abi in ['arm64-v8a','x86_64']}
    payload=bytes(image['entries'][0]['ciphertext'])
    native=z.read('lib/x86_64/libnexora_shield_native.so')
    at=native.find(payload)
    if at<0 or native.find(payload,at+1)>=0: raise SystemExit('Native corruption probe is ambiguous')
    corrupted=bytearray(native);corrupted[at+len(payload)-1]^=1
    with zipfile.ZipFile(root/'tampered-unsigned.apk','w') as out:
        for entry in z.infolist():
            out.writestr(copy.copy(entry),corrupted if entry.filename=='lib/x86_64/libnexora_shield_native.so' else z.read(entry))
from runtime_signing import prepare
if not (root/'ephemeral-test.p12').exists(): prepare(root,args.keytool)
env=os.environ.copy()
env['NEXORA_RUNTIME_TEST_PASSWORD']=(root/'signing-password.nshield-private').read_text()
key=root/'ephemeral-test.p12'
from runtime_guard_cases import build_cases, GUARD_PATH
cases={'baseline':baseline,'runtime':staged,'tampered':root/'tampered-unsigned.apk'}
cases.update(build_cases(root,staged,image))
if 'resigned' in cases:
    alternate=root/'alternate-signer'
    alternate.mkdir()
    prepare(alternate,args.keytool)
for name,source in cases.items():
    if name=='resigned':
        key=alternate/'ephemeral-test.p12'
        env['NEXORA_RUNTIME_TEST_PASSWORD']=(alternate/'signing-password.nshield-private').read_text()
    output=root/f'{name}.apk'
    subprocess.run([str(tools/'zipalign'),'-P','16','-f','4',str(source),str(output)],check=True)
    subprocess.run([str(tools/'apksigner'),'sign','--min-sdk-version','24','--ks',str(key),'--ks-key-alias','test','--ks-pass','env:NEXORA_RUNTIME_TEST_PASSWORD','--key-pass','env:NEXORA_RUNTIME_TEST_PASSWORD',str(output)],env=env,check=True)
    subprocess.run([str(tools/'apksigner'),'verify','--min-sdk-version','24',str(output)],check=True,capture_output=True)
    subprocess.run([str(tools/'zipalign'),'-c','-P','16','4',str(output)],check=True,capture_output=True)
    with zipfile.ZipFile(source) as before,zipfile.ZipFile(output) as after:
        if any(before.read(n)!=after.read(n) for n in before.namelist()): raise SystemExit('Signing altered a verified runtime payload')
evidence={'schema':1,'production_protected':False,'scope':'O.1 eligible data/asset/int-VM runtime','source_sha256':hashlib.sha256(baseline.read_bytes()).hexdigest(),'protected_strings':1,'virtualized_methods':1,'native_sha256':binaries,'smali_version':'3.0.9','min_sdk':28,'ndk_version':'27.3.13750724','alignment_verified':True,'signature_verified':True,'static_exposure_verified':True,'constant_exposure_probes_verified':True,'android_execution':'not-yet-run','artifacts':{name:hashlib.sha256((root/f'{name}.apk').read_bytes()).hexdigest() for name in cases}}
evidence.update({'effective_profile':'standard; partial runtime qualification',
    'source_commit':subprocess.run(['git','rev-parse','HEAD'],check=True,capture_output=True,text=True).stdout.strip(),
    'source_worktree_dirty':bool(subprocess.run(['git','status','--porcelain','--untracked-files=no'],check=True,capture_output=True,text=True).stdout.strip()),
    'executed_controls':['string-aead-decryption','constant-decryption','resource-bundle-runtime-decryption','asset-open-call-sites','native-jni-call-sites','integer-vm'],
    'protected_resources':sum(e['kind']=='Resource' for e in image['entries']),
    'protected_constants':sum(e['kind']=='Constant' for e in image['entries']),
    'protected_strings':sum(e['kind']=='String' for e in image['entries']),
    'virtualized_methods':sum(e['kind']=='IntVm' for e in image['entries']),
    'runtime_fingerprint':hashlib.sha256(json.dumps([image['schema'],image['application_id'],image['build_id'],image['entries'],image.get('guard_key'), image.get('guard_binding')],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest(),
    'apksigner_version':subprocess.run([str(tools/'apksigner'),'version'],check=True,capture_output=True,text=True).stdout.strip()})
if image.get('guard_key') is not None:
    with zipfile.ZipFile(staged) as z:
        graph_bytes=z.read(GUARD_PATH)
    payload=json.loads(bytes(json.loads(graph_bytes)['payload']))
    policy=json.loads(bytes(payload['runtime_policy']))
    evidence.update({'guard_selected':True,'rasp_mode':policy['mode'],'graph_nodes':len(payload['manifest']['graph']['nodes']),'graph_sha256':hashlib.sha256(graph_bytes).hexdigest()})
    evidence['executed_controls']+=['signed-integrity-graph','startup-provider','rasp-observations-policy']
(root/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
print('Signed APK hashes, 16 KiB alignment, payload identity and protected-data exposure verified')
