#!/usr/bin/env python3
"""Build an installable baseline APK with explicit string/VM golden methods."""
import argparse
import base64
import hashlib
import os
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
manifest = args.output / 'AndroidManifest.xml'
manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="dev.nexora.runtime">
<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35"/>
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
    output.writestr('assets/guard-probe.bin', b'nexora integrity resource fixture v1')
fd = os.open(args.output/'root.key', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as handle: handle.write(os.urandom(32))
print('Installable runtime fixture built; private root not printed')
