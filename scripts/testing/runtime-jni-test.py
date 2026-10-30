#!/usr/bin/env python3
"""Execute the real JNI exports through a JVM; exercise corruption refusal."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--image', type=Path, required=True)
p.add_argument('--library', type=Path, required=True)
p.add_argument('--java', default='java')
p.add_argument('--javac', default='javac')
p.add_argument('--ecj', type=Path)
args = p.parse_args()
image = json.loads(args.image.read_text())
fingerprint = hashlib.sha256(json.dumps([image['schema'], image['application_id'], image['build_id'], image['entries']], sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
string_slot = next(e['slot'] for e in image['entries'] if e['kind']=='String')
vm_slot = next(e['slot'] for e in image['entries'] if e['kind']=='IntVm')
with tempfile.TemporaryDirectory(prefix='nexora-jni-') as tmp:
    root = Path(tmp)
    source = root/'dev/nexora/shield/NativeShield.java'
    source.parent.mkdir(parents=True)
    source.write_text('''package dev.nexora.shield;
public final class NativeShield {
  private static native void nBind(String expected);
  private static native String nString(int slot);
  private static native int nInt(int slot, int[] arguments);
  public static void main(String[] args) {
    System.load(args[0]);
    try {
      nBind("NEXORA_RUNTIME_V1:FINGERPRINT");
      if (args.length>1) throw new AssertionError("tampered JNI runtime was accepted");
    } catch (SecurityException expected) {
      if (args.length>1) { System.out.println("HOST_JNI_TAMPER_REJECTED"); return; }
      throw expected;
    }
    String first=nString(STRING_SLOT).intern();
    if (!first.equals("Nexora_🔒_runtime_فارسی") || first != nString(STRING_SLOT).intern()) throw new AssertionError("string semantics");
    int[][] vectors={{1,2},{Integer.MAX_VALUE,1},{Integer.MIN_VALUE,-1},{0,0},{-18,9}};
    for(int[] v:vectors) if(nInt(VM_SLOT,v)!=v[0]+v[1]) throw new AssertionError("VM semantics");
    try {nString(VM_SLOT);throw new AssertionError("wrong kind accepted");}catch(SecurityException expected){}
    try {nInt(VM_SLOT,new int[]{1});throw new AssertionError("arity accepted");}catch(SecurityException expected){}
    try {nString(-1);throw new AssertionError("negative slot accepted");}catch(SecurityException expected){}
    System.out.println("HOST_JNI_OK");
  }
}'''.replace('FINGERPRINT',fingerprint).replace('STRING_SLOT',str(string_slot)).replace('VM_SLOT',str(vm_slot)),encoding='utf-8')
    compiler = [args.java,'-jar',str(args.ecj),'-1.8'] if args.ecj else [args.javac,'-source','8','-target','8']
    subprocess.run(compiler+['-encoding','UTF-8','-d',str(root),str(source)],check=True)
    command=[args.java,'-cp',str(root),'dev.nexora.shield.NativeShield']
    clean=subprocess.run(command+[str(args.library.resolve())],check=True,capture_output=True,text=True)
    if 'HOST_JNI_OK' not in clean.stdout: raise SystemExit('JNI positive execution evidence missing')
    binary=args.library.read_bytes()
    payload=bytes(image['entries'][0]['ciphertext'])
    at=binary.find(payload)
    if at<0 or binary.find(payload,at+1)>=0: raise SystemExit('Encrypted native entry location is absent or ambiguous')
    damaged=bytearray(binary);damaged[at+len(payload)-1]^=1
    corrupt=root/'corrupt.so';corrupt.write_bytes(damaged)
    rejected=subprocess.run(command+[str(corrupt),'reject'],check=True,capture_output=True,text=True)
    if 'HOST_JNI_TAMPER_REJECTED' not in rejected.stdout: raise SystemExit('JNI tamper evidence missing')
print('HOST_JNI_OK; HOST_JNI_TAMPER_REJECTED; no plaintext logged')
