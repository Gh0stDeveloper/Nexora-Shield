#!/usr/bin/env python3
"""Prove valid APKs fail only when incompatible raw-asset access is selected."""
import argparse
import copy
import os
from pathlib import Path
import subprocess
import zipfile

p=argparse.ArgumentParser()
p.add_argument('directory',type=Path)
p.add_argument('--example',type=Path,required=True)
p.add_argument('--tools',type=Path,required=True)
p.add_argument('--java',required=True)
a=p.parse_args();root=a.directory
classpath=os.pathsep.join(str(p) for p in sorted(a.tools.glob('*.jar')))
methods={
 'descriptor':'.method public static unsupported(Landroid/content/res/AssetManager;Ljava/lang/String;)V\n.registers 2\ninvoke-virtual {p0,p1}, Landroid/content/res/AssetManager;->openFd(Ljava/lang/String;)Landroid/content/res/AssetFileDescriptor;\nreturn-void\n.end method\n',
 'stream-cast':'.method public static unsupported(Landroid/content/res/AssetManager$AssetInputStream;)V\n.registers 1\nreturn-void\n.end method\n',
 'reflection':'.method public static unsupported(Ljava/lang/reflect/Method;)V\n.registers 1\nreturn-void\n.end method\n',
 'dynamic-loading':'.method public static unsupported(Ldalvik/system/DexClassLoader;)V\n.registers 1\nreturn-void\n.end method\n',
 'webview':'.method public static unsupported(Landroid/webkit/WebView;)V\n.registers 1\nreturn-void\n.end method\n',
}
for name,body in [*methods.items(),('native-access',None)]:
    directory=root/f'asset-contract-{name}';directory.mkdir()
    additions={}
    if body:
        source=directory/'smali';source.mkdir()
        (source/'Contract.smali').write_text('.class public Ldev/nexora/contract/Contract;\n.super Ljava/lang/Object;\n'+body)
        dex=directory/'classes2.dex'
        subprocess.run([a.java,'-cp',classpath,'com.android.tools.smali.smali.Main','assemble',str(source),'--api','28','--output',str(dex)],check=True,capture_output=True)
        additions['classes2.dex']=dex.read_bytes()
    else:
        additions['lib/x86_64/libfixture.so']=(root/'jniLibs/x86_64/libnexora_shield_native.so').read_bytes()
    apk=directory/'input.apk'
    with zipfile.ZipFile(root/'baseline-unsigned.apk') as before,zipfile.ZipFile(apk,'w') as out:
        for entry in before.infolist():out.writestr(copy.copy(entry),before.read(entry))
        for path,data in additions.items():out.writestr(path,data)
    command=[str(a.example),'prepare',str(apk),None,str(root/'root.key'),'dev.nexora.runtime','o1-asset-negative','Ldev/nexora/runtime/Probe;#secret']
    control=directory/'without-assets.nshield-private';command[3]=str(control)
    result=subprocess.run(command,check=False,capture_output=True,timeout=120)
    if result.returncode or not control.exists():raise SystemExit(f'Asset negative fixture is not valid: {name}')
    control.unlink()
    destination=directory/'with-assets.nshield-private';command[3]=str(destination)
    result=subprocess.run(command+['--asset','assets/secret-data.bin'],check=False,capture_output=True,timeout=120)
    if result.returncode==0 or destination.exists():raise SystemExit(f'Unverified asset access contract accepted: {name}')
print('ASSET_PLAN_NEGATIVE_OK: six valid APKs reject unverified access contracts')
