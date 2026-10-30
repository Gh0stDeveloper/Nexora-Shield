"""Adversarial APK variants; all are independently signed by the qualification harness."""
import hashlib
import copy
import json
import struct
import zipfile
import zlib

GUARD_PATH = 'assets/nexora-shield/guard.v1'

def build_cases(root, staged, image):
    if image.get('guard_key') is None:
        return {}
    cases = {}
    with zipfile.ZipFile(root/'baseline-unsigned.apk') as original:
        original_manifest = original.read('AndroidManifest.xml')
    with zipfile.ZipFile(staged) as source:
        def variant(name, replacements=None, removed=(), additions=None):
            destination = root/f'{name}-unsigned.apk'
            with zipfile.ZipFile(destination, 'w') as out:
                for entry in source.infolist():
                    if entry.filename not in removed:
                        out.writestr(copy.copy(entry), (replacements or {}).get(entry.filename, source.read(entry)))
                for path, data in (additions or {}).items():
                    out.writestr(path, data)
            cases[name] = destination
        envelope = json.loads(source.read(GUARD_PATH))
        envelope['signature'][0] ^= 1
        variant('guard-signature', {GUARD_PATH: json.dumps(envelope).encode()})
        variant('guard-missing', removed=[GUARD_PATH])
        resource = bytearray(source.read('assets/guard-probe.bin'))
        resource[0] ^= 1
        variant('resource-tampered', {'assets/guard-probe.bin': resource})
        if any(entry['kind']=='Resource' for entry in image['entries']):
            encrypted=bytearray(source.read('assets/secret-data.bin'))
            encrypted[-1]^=1
            variant('encrypted-asset-tampered', {'assets/secret-data.bin':encrypted})
        dex = bytearray(source.read('classes.dex'))
        before, after = b'preserved public constant', b'preserved public constanU'
        if dex.count(before) != 1:
            raise RuntimeError('DEX mutation probe is ambiguous')
        dex = dex.replace(before, after)
        dex[12:32] = hashlib.sha1(dex[32:]).digest()
        struct.pack_into('<I', dex, 8, zlib.adler32(dex[12:]) & 0xffffffff)
        variant('dex-tampered', {'classes.dex': dex})
        name = 'lib/x86_64/libnexora_shield_native.so'
        native = bytearray(source.read(name))
        native.extend(b"NEXORA_TAMPER_PROBE")
        variant('native-tampered', {name: native})
        variant('provider-removed', {'AndroidManifest.xml': original_manifest})
        variant('extra-entry', additions={'assets/unplanned.bin': b'unplanned'})
        foreign=(root/'unique/jniLibs/x86_64/libnexora_shield_native.so').read_bytes()
        variant('foreign-native', {'lib/x86_64/libnexora_shield_native.so':foreign})
        cases['resigned'] = staged
    return cases
