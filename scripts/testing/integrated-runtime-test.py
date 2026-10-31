#!/usr/bin/env python3
"""Exercise the actual shared transaction, with final-APK-bound evidence."""
import argparse,copy,hashlib,json,os,secrets,shutil,subprocess,zipfile
from pathlib import Path
from runtime_signing import private_write

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def tamper(out,tools,fixture,env):
    for label in ['native-tampered','provider-removed']:
        unsigned=out/f'{label}-unsigned.apk'
        with zipfile.ZipFile(out/'runtime.apk') as source,zipfile.ZipFile(unsigned,'w') as target:
            for e in source.infolist():
                if e.filename.startswith('META-INF/'):continue
                data=source.read(e)
                if label=='native-tampered' and e.filename=='lib/x86_64/libnexora_shield_native.so':data+=b'cross-transaction-tamper'
                if label=='provider-removed' and e.filename=='AndroidManifest.xml':
                    with zipfile.ZipFile(fixture/'baseline-unsigned.apk') as baseline:data=baseline.read(e.filename)
                target.writestr(e,data)
        aligned=out/f'{label}-aligned.apk'
        subprocess.run([str(tools/'zipalign'),'-P','16','-f','4',str(unsigned),str(aligned)],check=True,capture_output=True)
        subprocess.run([str(tools/'apksigner'),'sign','--min-sdk-version','28','--ks',str(fixture/'ephemeral-test.p12'),'--ks-key-alias','test','--ks-pass','env:NEXORA_RUNTIME_TEST_PASSWORD','--out',str(out/f'{label}.apk'),str(aligned)],env=env,check=True,capture_output=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('fixture',type=Path);p.add_argument('output',type=Path)
    for name in ['cli','cargo','rustc','java','ndk','build-tools']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--mode',choices=['report-only','enforce'],default='report-only');p.add_argument('--prepare-only',action='store_true');a=p.parse_args()
    repo=Path(__file__).resolve().parents[2];fixture=a.fixture.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    private_write(out/'retrace.key',secrets.token_bytes(32))
    c={'schema':1,'application_id':'dev.nexora.runtime','build_id':'o1-integrated','controls':[],
       'runtime_methods':['Ldev/nexora/runtime/Probe;#secret','Ldev/nexora/runtime/Probe;#sum','Ldev/nexora/runtime/Probe;#*Constant','Ldev/nexora/runtime/Probe;#constant'],
       'assets':['assets/secret-data.bin'],'root_key_file':str(fixture/'root.key'),'diversity_file':str(fixture/'diversity.nshield-private'),
       'graph_key_file':str(fixture/'guard-signing.key'),'signer_sha256':(fixture/'signer.sha256').read_text().strip(),'rasp_mode':a.mode,
       'dex':{'rename':True,'strip_metadata':True,'selectors':[{'kind':'class','class':'Ldev/nexora/runtime/Probe;'}]},
       'tools':{'java':str(a.java.absolute()),'smali_directory':str(repo/'build/tools/smali'),'cargo':str(a.cargo.absolute()),'rustc':str(a.rustc.absolute()),
                'native_source':str(repo),'ndk_directory':str(a.ndk.resolve()),'native_cache':str(repo/'target/o1-integrated-private-cache')},
       'retrace_key_file':str(out/'retrace.key'),'retrace_output':str(out/'retrace.nshield-map')}
    path=out/'engine.nshield-private';private_write(path,json.dumps(c).encode())
    if a.prepare_only:print('INTEGRATED_PRIVATE_CONFIGURATION_READY');return
    env=os.environ.copy();env['NEXORA_RUNTIME_TEST_PASSWORD']=(fixture/'signing-password.nshield-private').read_text()
    command=[str(a.cli.resolve()),'protect',str(fixture/'baseline-unsigned.apk'),'--output',str(out/'runtime.apk'),'--profile','maximum','--engine-config',str(path),
             '--keystore',str(fixture/'ephemeral-test.p12'),'--alias','test','--ks-pass-env','NEXORA_RUNTIME_TEST_PASSWORD','--min-sdk','28',
             '--zipalign',str(a.build_tools.resolve()/'zipalign'),'--apksigner',str(a.build_tools.resolve()/'apksigner'),'--public-report',str(out/'engine-report.json')]
    rejected=0
    cases=[('attestation','selected attestation',lambda v:v['controls'].append('attestation')),
           ('shared-retrace-key','retrace key must be independent',lambda v:v.update(retrace_key_file=v['root_key_file'])),
           ('unknown-field','invalid integrated configuration',lambda v:v.update(best_effort=True)),
           ('output-key-collision','aliases an input',lambda v:v.update(retrace_output=v['root_key_file'])),
           ('unsupported-method','NaN literal getter',lambda v:v['runtime_methods'].append('Ldev/nexora/runtime/Probe;#unsupportedNaN'))]
    for label,expected,change in cases:
        bad=copy.deepcopy(c);change(bad);private=out/f'{label}.nshield-private';private_write(private,json.dumps(bad).encode())
        cmd=command.copy();cmd[cmd.index('--engine-config')+1]=str(private)
        r=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=120)
        if r.returncode==0 or expected not in r.stderr or any((out/f).exists() for f in ['runtime.apk','engine-report.json','retrace.nshield-map']):raise RuntimeError(f'integrated fail-closed contract failed: {label}')
        rejected+=1
    subprocess.run(command,env=env,check=True,timeout=2400)
    report=json.loads((out/'engine-report.json').read_text());runtime=report['runtime'];dex=report['dex']
    if report['output_sha256']!=sha(out/'runtime.apk') or report['input_sha256']!=sha(fixture/'baseline-unsigned.apk') or dex['output_sha256']!=runtime['input_sha256']:raise RuntimeError('integrated APK evidence chain mismatch')
    if report['production_protected'] is not False or report['protection_scope']!='o1-integrated-experimental':raise RuntimeError('integrated scope was overstated')
    if [runtime['protected_strings'],runtime['protected_constants'],runtime['protected_resources'],runtime['virtualized_methods']]!=[1,5,1,1] or dex['name_records']==0 or dex['source_files_removed']==0:raise RuntimeError('composed execution is incomplete')
    if report['private_retrace_sha256']!=sha(out/'retrace.nshield-map'):raise RuntimeError('private retrace hash mismatch')
    subprocess.run([str(repo/'target/debug/examples/verify_integrated_retrace'),str(out/'engine-report.json'),str(out/'retrace.nshield-map'),str(out/'retrace.key'),str(out/'runtime.apk')],check=True,timeout=30)
    previous={f:sha(out/f) for f in ['runtime.apk','engine-report.json','retrace.nshield-map']}
    wrong=env.copy();wrong['NEXORA_RUNTIME_TEST_PASSWORD']=secrets.token_hex(24)
    failed=subprocess.run(command+['--force'],env=wrong,capture_output=True,text=True,timeout=2400)
    if failed.returncode==0 or 'signing failed' not in failed.stderr or any(sha(out/f)!=v for f,v in previous.items()):raise RuntimeError('failed signing damaged previous publication')
    subprocess.run(command+['--force'],env=env,check=True,timeout=2400)
    if any(sha(out/f)!=v for f,v in previous.items()):raise RuntimeError('complete private transaction did not reproduce')
    probes=[(fixture/'root.key').read_bytes(),(fixture/'guard-signing.key').read_bytes(),(out/'retrace.key').read_bytes()]
    d=(fixture/'diversity.nshield-private').read_bytes();probes.extend([d[7:39],d[39:]])
    with zipfile.ZipFile(out/'runtime.apk') as z:payloads=[z.read(n) for n in z.namelist()]
    payloads.append((out/'engine-report.json').read_bytes())
    if any(s in data for s in probes for data in payloads):raise RuntimeError('private material entered public payloads')
    shutil.copyfile(fixture/'baseline.apk',out/'baseline.apk');tamper(out,a.build_tools.resolve(),fixture,env)
    source=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
    dirty=bool(subprocess.check_output(['git','status','--porcelain','--untracked-files=no'],cwd=repo,text=True).strip())
    evidence={'schema':1,'production_protected':False,'scope':'o1-integrated-experimental','entrypoint':'cli','source_commit':source,'source_worktree_dirty':dirty,
              'android_execution':'not-yet-run','guard_selected':True,'rasp_mode':a.mode.replace('-','_'),'engine_report':report,'engine_report_sha256':sha(out/'engine-report.json'),
              'negative_configuration_cases':rejected,'failed_signing_preserved_outputs':True,'complete_private_transaction_reproduced':True,'private_inputs_absent':True,'retrace_final_apk_verified':True,
              'artifacts':{n:sha(out/f'{n}.apk') for n in ['baseline','runtime','native-tampered','provider-removed']}}
    (out/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print('INTEGRATED_TRANSACTION_OK: renamed DEX, runtime controls, final signature and encrypted final-APK retrace')
if __name__=='__main__':main()
