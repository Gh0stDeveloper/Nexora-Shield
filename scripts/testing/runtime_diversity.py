"""Private runtime diversity inputs and public final-payload comparisons."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import zipfile
from runtime_signing import private_write

MAGIC=b'NSDV1\0'

def prepare(root):
    seed=secrets.token_bytes(32)
    private_write(root/'diversity.nshield-private',MAGIC+b'\x01'+seed+secrets.token_hex(16).encode())
    unique(root)

def unique(root):
    value=(root/'diversity.nshield-private').read_bytes()
    if not value.startswith(MAGIC) or len(value)<40:raise RuntimeError('invalid private diversity configuration')
    private_write(root/'unique.nshield-private',MAGIC+b'\x00'+value[7:39]+secrets.token_hex(32).encode())

def digest(value):return hashlib.sha256(value).hexdigest()

def verify(root,inspector):
    repeated=root/'repeated';variant=root/'unique'
    image=json.loads((root/'runtime.nshield-private').read_text())
    repeat_image=json.loads((repeated/'runtime.nshield-private').read_text())
    unique_image=json.loads((variant/'runtime.nshield-private').read_text())
    if image!=repeat_image:raise RuntimeError('private runtime image did not reproduce')
    if 'diversity-v1-' not in image['build_id'] or image['build_id']==unique_image['build_id']:raise RuntimeError('diversity identity is missing or unchanged')
    if image['key_share_a']==unique_image['key_share_a']:raise RuntimeError('native generated constants did not diversify')
    if [e['slot'] for e in image['entries']]==[e['slot'] for e in unique_image['entries']]:raise RuntimeError('DEX binding slots did not diversify')
    parsed=subprocess.run([str(inspector),str(root/'runtime.nshield-private'),str(repeated/'runtime.nshield-private'),str(variant/'runtime.nshield-private')],check=True,capture_output=True,text=True,timeout=120)
    programs=json.loads(parsed.stdout)
    if len(programs)!=3 or any(len(p)!=1 for p in programs) or programs[0]!=programs[1]:raise RuntimeError('authenticated VM program did not reproduce')
    if any(p[0]['instruction_count']<=5 for p in programs):raise RuntimeError('qualified VM CFG transformation did not reach the encrypted runtime program')
    if programs[0][0]['opcode_map_sha256']==programs[2][0]['opcode_map_sha256'] or programs[0][0]['opcode_stream_sha256']==programs[2][0]['opcode_stream_sha256']:raise RuntimeError('actual VM opcode allocation/stream did not diversify')
    surfaces={}
    secret_inputs=[(root/'root.key').read_bytes(),(root/'guard-signing.key').read_bytes()]
    for p in ['diversity.nshield-private','unique.nshield-private']:
        b=(root/p).read_bytes();secret_inputs.extend([b[7:39],b[39:]])
    with zipfile.ZipFile(root/'runtime-unsigned.apk') as first,zipfile.ZipFile(repeated/'runtime-unsigned.apk') as repeat,zipfile.ZipFile(variant/'runtime-unsigned.apk') as other:
        if (root/'runtime-unsigned.apk').read_bytes()!=(repeated/'runtime-unsigned.apk').read_bytes():raise RuntimeError('rebuilt APK did not reproduce')
        if first.namelist()!=other.namelist():raise RuntimeError('diversity changed package entry identities')
        for name in first.namelist():
            for z in [first,repeat,other]:
                payload=z.read(name)
                if any(secret in payload for secret in secret_inputs):raise RuntimeError('private diversity material entered the APK')
            if name.startswith('lib/'):
                for z,configuration in [(first,image),(repeat,repeat_image),(other,unique_image)]:
                    binary=z.read(name)
                    if any(binary.count(bytes(entry['ciphertext']))!=1 for entry in configuration['entries']):raise RuntimeError('final native image does not contain the authenticated planned runtime payloads')
            if name.endswith('.dex') or name.startswith('lib/') or name=='assets/secret-data.bin':
                a,b=first.read(name),other.read(name)
                if a==b:raise RuntimeError(f'delivered surface did not diversify: {name}')
                surfaces[name]={'reproducible_private':digest(a),'unique_build':digest(b)}
            elif name!='assets/nexora-shield/guard.v1' and first.read(name)!=other.read(name):
                raise RuntimeError('unselected package payload changed during diversification')
        graphs=[]
        for z in [first,other]:
            guard=json.loads(z.read('assets/nexora-shield/guard.v1'))
            graphs.append(json.loads(bytes(guard['payload']))['manifest'])
        if any(g.get('topology')!='certificate_tree' for g in graphs):raise RuntimeError('signed diversified topology missing')
        if graphs[0]['graph']['edges']==graphs[1]['graph']['edges']:raise RuntimeError('integrity topology did not diversify')
        if graphs[0]['distribution']['checks']==graphs[1]['distribution']['checks']:raise RuntimeError('integrity check assignment did not diversify')
        for name,items in [('integrity_edges',[g['graph']['edges'] for g in graphs]),('distributed_checks',[g['distribution']['checks'] for g in graphs])]:
            surfaces[name]={'reproducible_private':digest(json.dumps(items[0],sort_keys=True).encode()),'unique_build':digest(json.dumps(items[1],sort_keys=True).encode())}
    for abi in ['arm64-v8a','x86_64']:
        a=(root/f'jniLibs/{abi}/libnexora_shield_native.so').read_bytes()
        b=(repeated/f'jniLibs/{abi}/libnexora_shield_native.so').read_bytes()
        if a!=b:raise RuntimeError('independently compiled native library did not reproduce')
    result={'schema':1,'private_inputs_absent':True,'runtime_image_reproduced':True,'native_libraries_reproduced':True,'rebuilt_apk_reproduced':True,'unsigned_apk_sha256':digest((root/'runtime-unsigned.apk').read_bytes()),'unique_unsigned_apk_sha256':digest((variant/'runtime-unsigned.apk').read_bytes()),'surfaces':surfaces,'vm_programs':{'reproducible_private':programs[0],'unique_build':programs[2]},'vm_cfg_materialized':True,'vm_opcode_map_varied':True,'final_native_payloads_verified':True}
    (root/'diversity-evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    print('DELIVERED_DIVERSITY_OK: independent private reproduction and actual DEX/data/native/graph variation')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('operation',choices=['prepare','unique','verify']);p.add_argument('directory',type=Path);p.add_argument('--inspector',type=Path);a=p.parse_args()
    if a.operation=='verify':
        if a.inspector is None:p.error('verify requires --inspector')
        verify(a.directory,a.inspector)
    else:{'prepare':prepare,'unique':unique}[a.operation](a.directory)
