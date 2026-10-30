#!/usr/bin/env python3
"""Negative integration cases against a real compiled-manifest APK."""
import argparse
from pathlib import Path
import subprocess
import struct
import zipfile

p = argparse.ArgumentParser()
p.add_argument('directory', type=Path)
p.add_argument('--example', type=Path, required=True)
p.add_argument('--tools', type=Path, required=True)
p.add_argument('--java', required=True)
args = p.parse_args()
root = args.directory
base = root/'baseline-unsigned.apk'
key = root/'root.key'
def run(operation, output, application, build, selectors, extra=(), source=base):
    return subprocess.run([str(args.example), operation, str(source), str(output), str(key), application, build, *selectors, *extra], capture_output=True, text=True, timeout=240)
secret = 'Ldev/nexora/runtime/Probe;#secret'
if (root/'guard-signing.key').exists():
    destination=root/'reused-client-key.nshield-private'
    result=run('prepare',destination,'dev.nexora.runtime','o1-functional',[secret],
        ['--guard-key',str(key),'--signer-sha',str(root/'signer.sha256'),'--rasp','enforce'])
    if result.returncode==0 or destination.exists():
        raise SystemExit('Client root was accepted as APK graph signing key')
for name, app, selectors in [
    ('wrong-package', 'dev.wrong.package', [secret]),
    ('instance-method', 'dev.nexora.runtime', ['Ldev/nexora/runtime/MainActivity;#onCreate']),
    ('missing-method', 'dev.nexora.runtime', ['Ldev/nexora/runtime/Probe;#missing']),
    ('duplicate-selector', 'dev.nexora.runtime', [secret, secret]),
    ('unsupported-nan', 'dev.nexora.runtime', ['Ldev/nexora/runtime/Probe;#unsupportedNaN']),
    ('unsupported-byte', 'dev.nexora.runtime', ['Ldev/nexora/runtime/Probe;#unsupportedByte']),
]:
    destination = root/f'{name}.nshield-private'
    result = run('prepare', destination, app, 'o1-functional', selectors)
    if result.returncode == 0 or destination.exists():
        raise SystemExit(f'Unsafe runtime selection was accepted: {name}')
destination = root/'wrong-native-binding.apk'
result = run('stage', destination, 'dev.nexora.runtime', 'different-build',
             [secret, 'Ldev/nexora/runtime/Probe;#sum'],
             ['--tools', str(args.tools), '--java', args.java, '--native', str(root/'jniLibs')])
if result.returncode == 0 or destination.exists():
    raise SystemExit('Mismatched native build was accepted')
destination = root/'already-bound.nshield-private'
result = run('prepare', destination, 'dev.nexora.runtime', 'o1-functional',
             [secret], source=root/'runtime-unsigned.apk')
if result.returncode == 0 or destination.exists():
    raise SystemExit('Existing runtime namespace was accepted')
with zipfile.ZipFile(base) as z:
    manifest = bytearray(z.read('AndroidManifest.xml'))
    if manifest[:2] != b'\x03\x00':
        raise SystemExit('Negative matrix requires a compiled manifest')
    # The positive fixture has exactly one numeric SDK value of 24.
    offset = 8
    changed = 0
    while offset < len(manifest):
        kind, header, size = struct.unpack_from('<HHI', manifest, offset)
        if kind == 0x102:
            first, stride, count = struct.unpack_from('<HHH', manifest, offset + 24)
            for index in range(count):
                at = offset + 16 + first + index * stride
                if manifest[at + 15] in (0x10, 0x11) and struct.unpack_from('<I', manifest, at + 16)[0] == 24:
                    struct.pack_into('<I', manifest, at + 16, 23)
                    changed += 1
        offset += size
    if changed != 1:
        raise SystemExit('SDK negative probe is ambiguous')
    low_sdk = root/'unsupported-sdk.apk'
    with zipfile.ZipFile(low_sdk, 'w') as output:
        for entry in z.infolist():
            output.writestr(entry, manifest if entry.filename == 'AndroidManifest.xml' else z.read(entry))
destination = root/'unsupported-sdk.nshield-private'
result = run('prepare', destination, 'dev.nexora.runtime', 'o1-functional', [secret], source=low_sdk)
if result.returncode == 0 or destination.exists():
    raise SystemExit('Unsupported Android API contract was accepted')
print('RUNTIME_PLAN_NEGATIVE_OK: identity, eligibility, selection and native binding')
