#!/usr/bin/env python3
"""Private ephemeral signing material for the authorized Android qualification fixture."""
import argparse
import hashlib
import os
from pathlib import Path
import secrets
import subprocess

def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)

def prepare(root, keytool='keytool'):
    if (root/'ephemeral-test.p12').exists():
        raise RuntimeError('Signing fixture already exists')
    password = secrets.token_hex(24)
    env = os.environ.copy()
    env['NEXORA_RUNTIME_TEST_PASSWORD'] = password
    key = root/'ephemeral-test.p12'
    subprocess.run([keytool, '-genkeypair', '-noprompt', '-keystore', str(key),
        '-storetype', 'PKCS12', '-storepass:env', 'NEXORA_RUNTIME_TEST_PASSWORD',
        '-keypass:env', 'NEXORA_RUNTIME_TEST_PASSWORD', '-alias', 'test',
        '-keyalg', 'RSA', '-keysize', '2048', '-validity', '2',
        '-dname', 'CN=Nexora Runtime Ephemeral Test'],
        env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key.chmod(0o600)
    der = subprocess.run([keytool, '-exportcert', '-keystore', str(key),
        '-storepass:env', 'NEXORA_RUNTIME_TEST_PASSWORD', '-alias', 'test'],
        env=env, check=True, capture_output=True).stdout
    private_write(root/'signing-password.nshield-private', password.encode())
    private_write(root/'signer.sha256', hashlib.sha256(der).hexdigest().encode())
    private_write(root/'guard-signing.key', secrets.token_bytes(32))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', type=Path)
    parser.add_argument('--keytool', default='keytool')
    args = parser.parse_args()
    prepare(args.directory, args.keytool)
    print('Independent graph key and ephemeral signer prepared; no private material printed')
