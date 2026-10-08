#!/usr/bin/env python3
"""Deterministic, synthetic and non-installable DEX-bearing APK fixtures for O.1.

Based on the existing Phase B golden DEX fixture generator.
Do not treat these files as representative Android installation tests.
"""
import zipfile
import hashlib
import struct
import zlib
from pathlib import Path

DEX_HEADER_SIZE = 0x70
DEX_ENDIAN_CONSTANT = 0x12345678

def uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            byte |= 0x80
        out.append(byte)
        if not value:
            return bytes(out)

def put_u16(buf: bytearray, off: int, value: int) -> None:
    buf[off:off + 2] = struct.pack("<H", value)

def put_u32(buf: bytearray, off: int, value: int) -> None:
    buf[off:off + 4] = struct.pack("<I", value)

def build(path: Path, descriptor: str, method_name: str) -> None:
    strings = [
        descriptor,
        "Ljava/lang/Object;",
        "V",
        method_name,
        "A.java",
    ]

    string_ids_off = DEX_HEADER_SIZE
    type_ids_off = string_ids_off + len(strings) * 4
    proto_ids_off = type_ids_off + 3 * 4
    method_ids_off = proto_ids_off + 12
    class_defs_off = method_ids_off + 8
    data_off = class_defs_off + 32

    data = bytearray(data_off)
    string_offsets = []
    for value in strings:
        string_offsets.append(len(data))
        data += uleb(len(value.encode("utf-16-le")) // 2)
        data += value.encode("ascii")
        data.append(0)

    while len(data) % 4:
        data.append(0)

    code_off = len(data)
    data += struct.pack("<HHHHIIH", 0, 0, 0, 0, 0, 1, 0x000e)

    class_data_off = len(data)
    data += uleb(0)
    data += uleb(0)
    data += uleb(1)
    data += uleb(0)
    data += uleb(0)
    data += uleb(0x0009)
    data += uleb(code_off)

    file_size = len(data)
    data[0:8] = b"dex\n035\0"
    put_u32(data, 32, file_size)
    put_u32(data, 36, DEX_HEADER_SIZE)
    put_u32(data, 40, DEX_ENDIAN_CONSTANT)
    put_u32(data, 44, 0)
    put_u32(data, 48, 0)
    put_u32(data, 52, 0)
    put_u32(data, 56, len(strings))
    put_u32(data, 60, string_ids_off)
    put_u32(data, 64, 3)
    put_u32(data, 68, type_ids_off)
    put_u32(data, 72, 1)
    put_u32(data, 76, proto_ids_off)
    put_u32(data, 80, 0)
    put_u32(data, 84, 0)
    put_u32(data, 88, 1)
    put_u32(data, 92, method_ids_off)
    put_u32(data, 96, 1)
    put_u32(data, 100, class_defs_off)
    put_u32(data, 104, file_size - data_off)
    put_u32(data, 108, data_off)

    for index, offset in enumerate(string_offsets):
        put_u32(data, string_ids_off + index * 4, offset)

    put_u32(data, type_ids_off, 0)
    put_u32(data, type_ids_off + 4, 1)
    put_u32(data, type_ids_off + 8, 2)

    put_u32(data, proto_ids_off, 2)
    put_u32(data, proto_ids_off + 4, 2)
    put_u32(data, proto_ids_off + 8, 0)

    put_u16(data, method_ids_off, 0)
    put_u16(data, method_ids_off + 2, 0)
    put_u32(data, method_ids_off + 4, 3)

    put_u32(data, class_defs_off, 0)
    put_u32(data, class_defs_off + 4, 1)
    put_u32(data, class_defs_off + 8, 1)
    put_u32(data, class_defs_off + 12, 0)
    put_u32(data, class_defs_off + 16, 4)
    put_u32(data, class_defs_off + 20, 0)
    put_u32(data, class_defs_off + 24, class_data_off)
    put_u32(data, class_defs_off + 28, 0)

    data[12:32] = hashlib.sha1(data[32:]).digest()
    put_u32(data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    path.write_bytes(data)

Path("build/phase-o1").mkdir(parents=True, exist_ok=True)

build(Path("build/phase-o1/classes.dex"), "Lcom/test/A;", "run")
build(Path("build/phase-o1/classes2.dex"), "Lcom/test/B;", "go")

directory = Path("build/phase-o1")
directory.mkdir(parents=True, exist_ok=True)
manifest = b'<manifest package="dev.nexora.phaseo1"/>'
first = (directory / "classes.dex").read_bytes()
second = (directory / "classes2.dex").read_bytes()

with zipfile.ZipFile(directory / "valid.apk", "w", compression=zipfile.ZIP_STORED) as output:
    output.writestr("AndroidManifest.xml", manifest)
    output.writestr("classes.dex", first)
    output.writestr("classes2.dex", second)

with zipfile.ZipFile(directory / "invalid-dex.apk", "w", compression=zipfile.ZIP_STORED) as output:
    output.writestr("AndroidManifest.xml", manifest)
    output.writestr("classes.dex", b"not valid dex")

with zipfile.ZipFile(directory / "compressed-dex.apk", "w", compression=zipfile.ZIP_DEFLATED) as output:
    output.writestr("AndroidManifest.xml", manifest)
    output.writestr("classes.dex", first)

with zipfile.ZipFile(directory / "duplicate-class.apk", "w", compression=zipfile.ZIP_STORED) as output:
    output.writestr("AndroidManifest.xml", manifest)
    output.writestr("classes.dex", first)
    output.writestr("classes2.dex", first)

print("Phase O.1 stored valid / malformed / compressed / duplicate-class fixtures created.")
