#!/usr/bin/env python3
"""Run the actual plugin and Studio adapters on a compiled Android APK."""
import argparse,copy,hashlib,json,os,shutil,subprocess
from pathlib import Path
from runtime_signing import private_write
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
p=argparse.ArgumentParser();p.add_argument('fixture',type=Path);p.add_argument('integrated',type=Path);p.add_argument('--cli',type=Path,required=True);p.add_argument('--gradle',required=True);p.add_argument('--sdk',type=Path,required=True);a=p.parse_args()
repo=Path(__file__).resolve().parents[2];fixture=a.fixture.resolve();parent=a.integrated.resolve();original=json.loads((parent/'engine.nshield-private').read_text());base=json.loads((parent/'evidence.json').read_text())
env=os.environ.copy();env.update(NEXORA_INTEGRATED_BASELINE_FIXTURE=str(fixture),NEXORA_SHIELD_CLI=str(a.cli.resolve()),NEXORA_RUNTIME_TEST_PASSWORD=(fixture/'signing-password.nshield-private').read_text(),ANDROID_SDK_ROOT=str(a.sdk.resolve()))
for module,entrypoint,report_name in [('gradle-plugin','gradle-plugin','baseline-unsigned.json'),('studio','shield-studio','runtime.json')]:
    out=parent/module;out.mkdir();c=copy.deepcopy(original);c['retrace_output']=str(out/'retrace.nshield-map');private_write(out/'engine.nshield-private',json.dumps(c).encode());env['NEXORA_INTEGRATED_EXECUTION']=str(out)
    subprocess.run([a.gradle,'-p',str(repo/module),'integratedEngineTest','--no-daemon','--stacktrace'],env=env,check=True,timeout=1800)
    report=json.loads((out/report_name).read_text())
    if report['output_sha256']!=sha(out/'runtime.apk') or report['protection_scope']!='o1-integrated-experimental' or report['production_protected'] is not False:raise RuntimeError('frontend did not execute actual integrated engine')
    shutil.copyfile(out/report_name,out/'engine-report.json')
    subprocess.run([str(repo/'target/debug/examples/verify_integrated_retrace'),str(out/'engine-report.json'),str(out/'retrace.nshield-map'),c['retrace_key_file'],str(out/'runtime.apk')],check=True,timeout=30)
    e={'schema':1,'production_protected':False,'scope':'o1-integrated-experimental','entrypoint':entrypoint,'source_commit':base['source_commit'],'source_worktree_dirty':base['source_worktree_dirty'],
       'android_execution':'not-yet-run','guard_selected':True,'rasp_mode':base['rasp_mode'],'engine_report':report,'engine_report_sha256':sha(out/'engine-report.json'),
       'retrace_final_apk_verified':True,'artifacts':{'runtime':sha(out/'runtime.apk')}}
    (out/'evidence.json').write_text(json.dumps(e,indent=2)+'\n');print(f'INTEGRATED_FRONTEND_OK: {entrypoint}, actual signed APK and final-APK retrace')
