#!/usr/bin/env python3
"""Fetch the exact trusted Smali 3.0.9 CLI classpath; reject changed bytes."""
import hashlib
import json
import pathlib
import sys
import urllib.request

root = pathlib.Path(__file__).resolve().parents[2]
output = pathlib.Path(sys.argv[1] if len(sys.argv) == 2 else root / 'build/tools/smali')
output.mkdir(parents=True, exist_ok=True)
catalog = json.loads((root / 'tools/smali-3.0.9.json').read_text())
for entry in catalog['artifacts']:
    path = output / entry['name']
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
        with urllib.request.urlopen(entry['url'], timeout=60) as response:
            data = response.read(8 * 1024 * 1024 + 1)
        if len(data) > 8 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise SystemExit('Smali artifact checksum mismatch')
        path.write_bytes(data)
print('Pinned Smali 3.0.9 classpath verified')
