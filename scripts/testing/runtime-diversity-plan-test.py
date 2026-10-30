#!/usr/bin/env python3
"""Diversity configuration failures must not create any runtime image/APK."""
import argparse
from pathlib import Path
import subprocess
from runtime_signing import private_write
from runtime_diversity import MAGIC

p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--example',type=Path,required=True);a=p.parse_args();r=a.directory
original=(r/'diversity.nshield-private').read_bytes()
variants={'short':b'x','wrong-magic':b'X'+original[1:],'wrong-mode':original[:6]+b'\xff'+original[7:],'empty-id':original[:39],'invalid-utf8':original[:39]+b'\xff','public-mode':original,'wrong-suffix':original,'reused-client':MAGIC+b'\x01'+(r/'root.key').read_bytes()+b'reproduction'}
for label,data in variants.items():
 path=r/(f'diversity-negative-{label}.bin' if label=='wrong-suffix' else f'diversity-negative-{label}.nshield-private');private_write(path,data)
 if label=='public-mode':path.chmod(0o644)
 output=r/f'diversity-rejected-{label}.nshield-private'
 command=[str(a.example),'prepare',str(r/'baseline-unsigned.apk'),str(output),str(r/'root.key'),'dev.nexora.runtime','o1-functional','Ldev/nexora/runtime/Probe;#secret','--diversity-file',str(path)]
 result=subprocess.run(command,check=False,capture_output=True,timeout=120)
 if result.returncode==0 or output.exists():raise SystemExit(f'Unsafe diversity configuration accepted: {label}')
key=r/'diversity-negative-reused-signing.key';private_write(key,original[7:39])
output=r/'diversity-rejected-signing.nshield-private'
command=[str(a.example),'prepare',str(r/'baseline-unsigned.apk'),str(output),str(r/'root.key'),'dev.nexora.runtime','o1-functional','Ldev/nexora/runtime/Probe;#secret','--diversity-file',str(r/'diversity.nshield-private'),'--guard-key',str(key),'--signer-sha',str(r/'signer.sha256'),'--rasp','enforce']
result=subprocess.run(command,check=False,capture_output=True,timeout=120)
if result.returncode==0 or output.exists():raise SystemExit('Private diversity seed was accepted as graph signing key')
print('DIVERSITY_PLAN_NEGATIVE_OK: malformed/private inputs and client/graph key separation')
