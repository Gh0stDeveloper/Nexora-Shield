#!/usr/bin/env python3
"""Build an installable baseline APK with explicit string/VM golden methods."""
import argparse
import base64
import hashlib
import os
import struct
from pathlib import Path
import subprocess
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('output', type=Path)
parser.add_argument('--java', default='java')
parser.add_argument('--smali', type=Path, required=True)
parser.add_argument('--aapt2', type=Path, required=True)
parser.add_argument('--android-jar', type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)
source = args.output / 'smali/dev/nexora/runtime'
source.mkdir(parents=True)
probe = 'Nexora_🔒_runtime_فارسی'
digest = base64.b64encode(hashlib.sha256(probe.encode()).digest()).decode()
(source / 'Probe.smali').write_text(f'''.class public final Ldev/nexora/runtime/Probe;
.super Ljava/lang/Object;
.source "Probe.java"
.field public static final untouched:Ljava/lang/String; = "preserved public constant"

.method public static secret()Ljava/lang/String;
    .registers 1
    const-string v0, "{probe}"
    return-object v0
.end method

.method public static sum(II)I
    .registers 3
    add-int v0, p0, p1
    return v0
.end method

.method public static unsupportedNaN()F
    .registers 1
    const v0, 0x7fc00001
    return v0
.end method

.method public static unsupportedByte()B
    .registers 1
    const/4 v0, 0x7
    return v0
.end method
''', encoding='utf-8')
(source / 'MainActivity.smali').write_text(f'''.class public Ldev/nexora/runtime/MainActivity;
.super Landroid/app/Activity;

.method public constructor <init>()V
    .registers 1
    invoke-direct {{p0}}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .registers 7
    invoke-super {{p0, p1}}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    :try_start
    invoke-static {{}}, Ldev/nexora/runtime/Probe;->secret()Ljava/lang/String;
    move-result-object v0
    const-string v1, "SHA-256"
    invoke-static {{v1}}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    move-result-object v1
    const-string v2, "UTF-8"
    invoke-virtual {{v0, v2}}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B
    move-result-object v0
    invoke-virtual {{v1, v0}}, Ljava/security/MessageDigest;->digest([B)[B
    move-result-object v0
    const/4 v1, 0x2
    invoke-static {{v0, v1}}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;
    move-result-object v0
    const-string v1, "{digest}"
    invoke-virtual {{v1, v0}}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    if-eqz v0, :failed
    invoke-static {{}}, Ldev/nexora/runtime/Probe;->secret()Ljava/lang/String;
    move-result-object v0
    invoke-static {{}}, Ldev/nexora/runtime/Probe;->secret()Ljava/lang/String;
    move-result-object v1
    if-ne v0, v1, :failed
    const v0, 0x7fffffff
    const/4 v1, 0x1
    invoke-static {{v0, v1}}, Ldev/nexora/runtime/Probe;->sum(II)I
    move-result v0
    const v1, -0x80000000
    if-ne v0, v1, :failed
    const-string v0, "NEXORA_RUNTIME_OK"
    goto :report
    :failed
    new-instance v0, Ljava/lang/AssertionError;
    invoke-direct {{v0}}, Ljava/lang/AssertionError;-><init>()V
    throw v0
    :try_end
    .catch Ljava/lang/Throwable; {{:try_start .. :try_end}} :catch
    :catch
    move-exception v0
    instance-of v1, v0, Ljava/lang/SecurityException;
    if-nez v1, :rejected
    instance-of v1, v0, Ljava/lang/ExceptionInInitializerError;
    if-eqz v1, :unexpected
    invoke-virtual {{v0}}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;
    move-result-object v0
    instance-of v1, v0, Ljava/lang/SecurityException;
    if-eqz v1, :unexpected
    :rejected
    const-string v0, "NEXORA_RUNTIME_REJECTED"
    goto :report
    :unexpected
    const-string v0, "NEXORA_RUNTIME_UNEXPECTED_FAILURE"
    :report
    const-string v1, "NexoraRuntime"
    invoke-static {{v1, v0}}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    invoke-virtual {{p0, v0}}, Landroid/app/Activity;->setTitle(Ljava/lang/CharSequence;)V
    return-void
.end method
''', encoding='utf-8')

constant_methods = [
    ('booleanConstant', 'Z', 'const/4 v0, 0x1', 'return v0'),
    ('constant', 'I', 'const v0, 0x13579bdf', 'return v0'),
    ('longConstant', 'J', 'const-wide v0, 0x123456789abcdefL', 'return-wide v0'),
    ('floatConstant', 'F', 'const/high16 v0, -0x80000000', 'return v0'),
    ('doubleConstant', 'D', 'const-wide/high16 v0, 0x4004000000000000L', 'return-wide v0'),
]
probe_source=source/'Probe.smali'
with probe_source.open('a') as out:
    for name,kind,load,ret in constant_methods:
        out.write(f'\n.method public static {name}(){kind}\n    .registers 2\n    {load}\n    {ret}\n.end method\n')
(source/'QA.smali').write_text('''.class public final Ldev/nexora/runtime/QA;
.super Ljava/lang/Object;
.method public static assertDigest(Ljava/lang/String;Ljava/lang/String;)V
    .registers 5
    const-string v0, "SHA-256"
    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    move-result-object v0
    const-string v1, "UTF-8"
    invoke-virtual {p0, v1}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B
    move-result-object v1
    invoke-virtual {v0, v1}, Ljava/security/MessageDigest;->digest([B)[B
    move-result-object v0
    const/4 v1, 0x2
    invoke-static {v0, v1}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;
    move-result-object v0
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0
    if-nez v0, :ok
    new-instance v0, Ljava/lang/AssertionError;
    invoke-direct {v0}, Ljava/lang/AssertionError;-><init>()V
    throw v0
    :ok
    return-void
.end method
''')
checks=[]
values={'Z':'true','I':str(0x13579bdf),'J':str(0x123456789abcdef),'F':str(-2147483648),'D':str(struct.unpack('<q',struct.pack('<d',2.5))[0])}
for name,kind,_,_ in constant_methods:
    wide=kind in ['J','D']
    code=f'    invoke-static {{}}, Ldev/nexora/runtime/Probe;->{name}(){kind}\n    '+('move-result-wide' if wide else 'move-result')+' v0\n'
    if kind=='F':
        code+='    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I\n    move-result v0\n'
    elif kind=='D':
        code+='    invoke-static {v0, v1}, Ljava/lang/Double;->doubleToRawLongBits(D)J\n    move-result-wide v0\n'
    owner,ty=('Boolean','Z') if kind=='Z' else ('Long','J') if wide else ('Integer','I')
    registers='{v0, v1}' if wide else '{v0}'
    code+=f'    invoke-static {registers}, Ljava/lang/{owner};->toString({ty})Ljava/lang/String;\n    move-result-object v0\n'
    expected=base64.b64encode(hashlib.sha256(values[kind].encode()).digest()).decode()
    code+=f'    const-string v1, "{expected}"\n    invoke-static {{v0, v1}}, Ldev/nexora/runtime/QA;->assertDigest(Ljava/lang/String;Ljava/lang/String;)V\n'
    checks.append(code)
activity=source/'MainActivity.smali'
body=activity.read_text().replace('    const-string v0, "NEXORA_RUNTIME_OK"', ''.join(checks)+'    const-string v0, "NEXORA_RUNTIME_OK"')
activity.write_text(body)

asset_payload=b'Nexora private asset v1\x00\xff'+bytes(range(256))*20
asset_cases=[('secret-data.bin',asset_payload),('guard-probe.bin',b'nexora integrity resource fixture v1')]
asset_calls=[]
for name,data in asset_cases:
    expected=base64.b64encode(hashlib.sha256(data).digest()).decode()
    for mode in [0,1]:
        asset_calls.append(f'''    invoke-virtual {{p0}}, Landroid/app/Activity;->getAssets()Landroid/content/res/AssetManager;
    move-result-object v0
    const-string v1, "{name}"
    const-string v2, "{expected}"
    const/4 v3, 0x{mode:x}
    invoke-static {{v0, v1, v2, v3}}, Ldev/nexora/runtime/QA;->assertAsset(Landroid/content/res/AssetManager;Ljava/lang/String;Ljava/lang/String;I)V
''')
activity.write_text(activity.read_text().replace('    const-string v0, "NEXORA_RUNTIME_OK"',''.join(asset_calls)+'    const-string v0, "NEXORA_RUNTIME_OK"'))
with (source/'QA.smali').open('a') as out:
    out.write((Path(__file__).with_name('runtime-asset-qa.smali')).read_text())

manifest = args.output / 'AndroidManifest.xml'
manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="dev.nexora.runtime">
<uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/>
<application android:label="Nexora Runtime QA" android:hasCode="true" android:extractNativeLibs="true">
<activity android:name=".MainActivity" android:exported="true"><intent-filter>
<action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/>
</intent-filter></activity></application></manifest>''')
subprocess.run([str(args.aapt2), 'link', '-o', str(args.output / 'resources.apk'), '--manifest', str(manifest), '-I', str(args.android_jar)], check=True)
classpath = os.pathsep.join(str(p) for p in sorted(args.smali.glob('*.jar')))
subprocess.run([args.java, '-cp', classpath, 'com.android.tools.smali.smali.Main', 'assemble', str(args.output/'smali'), '--api', '24', '--output', str(args.output/'classes.dex')], check=True)
with zipfile.ZipFile(args.output/'resources.apk') as original, zipfile.ZipFile(args.output/'baseline-unsigned.apk', 'w') as output:
    for entry in original.infolist(): output.writestr(entry, original.read(entry))
    output.writestr('classes.dex', (args.output/'classes.dex').read_bytes())
    for name,data in asset_cases: output.writestr('assets/'+name,data)
fd = os.open(args.output/'root.key', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as handle: handle.write(os.urandom(32))
print('Installable runtime fixture built; private root not printed')
