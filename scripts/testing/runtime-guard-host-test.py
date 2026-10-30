#!/usr/bin/env python3
"""Host integration of the signed graph; device tests collect Android identity separately."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser()
p.add_argument('directory', type=Path)
p.add_argument('--verifier', type=Path, required=True)
args = p.parse_args()
root = args.directory
evidence = json.loads((root/'evidence.json').read_text())
for name, expected_hash in evidence['artifacts'].items():
    apk = root/f'{name}.apk'
    if hashlib.sha256(apk.read_bytes()).hexdigest() != expected_hash:
        raise SystemExit('Host verification requires exact final APK bytes')
    certificate = root/'alternate-signer/signer.sha256' if name == 'resigned' else root/'signer.sha256'
    result = subprocess.run([str(args.verifier), str(apk), str(root/'runtime.nshield-private'),
        str(certificate), 'dev.nexora.runtime', '0'], capture_output=True, text=True, timeout=120)
    if (result.returncode == 0) != (name == 'runtime'):
        raise SystemExit(f'Wrong host integrity outcome: {name}')
    if name == 'runtime' and 'RASP_POLICY_VERIFIED' not in result.stdout:
        raise SystemExit('Bound RASP response contract was not exercised')
print(f'HOST_APK_GRAPH_MATRIX_OK: artifacts={len(evidence["artifacts"])}')
