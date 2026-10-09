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

# O.1.3: non-DEX Android ABI regressions. These fixture APKs must be
# rejected by the diagnostic staging gate before it writes an output file.
abi_variants = {
    "manifest-component": (
        b'<manifest package="com.test"><application android:name=".A"/></manifest>',
        {},
    ),
    "manifest-fully-qualified": (
        b'<manifest package="com.test"><activity android:name="com.test.A"/></manifest>',
        {},
    ),
    "manifest-binary": (
        b"\x03\x00\x08\x00\x08\x00\x00\x00",
        {},
    ),
    "resource-callback": (
        manifest,
        {"res/layout/screen.xml": b'<Button android:onClick="run"/>'},
    ),
    "resource-config": (
        manifest,
        {"assets/config.json": b'{"entryClass":"com.test.A"}'},
    ),
    "resource-binary": (
        manifest,
        {"res/layout/main.xml": b"\x03\x00\x08\x00\x08\x00\x00\x00"},
    ),
    "resource-table": (
        manifest,
        {"resources.arsc": b"\x02\x00\x0c\x00"},
    ),
    "native-jni": (
        manifest,
        {"lib/arm64-v8a/libexample.so": b"\x7fELF\x02\x01"},
    ),
}
for variant, (variant_manifest, extras) in abi_variants.items():
    with zipfile.ZipFile(directory / f"{variant}.apk", "w", compression=zipfile.ZIP_STORED) as output:
        output.writestr("AndroidManifest.xml", variant_manifest)
        output.writestr("classes.dex", first)
        output.writestr("classes2.dex", second)
        for extra_name, payload in extras.items():
            output.writestr(extra_name, payload)

# Strict, structurally valid synthetic Android binary XML with a UTF-8
# string pool, empty start/end manifest nodes and optional resource map.
# These are parser-contract fixtures, not installable Android manifests.
def binary_manifest(values: list[str], include_resource_map: bool = True) -> bytes:
    strings_data = bytearray()
    offsets = []
    for value in values:
        raw = value.encode("utf-8")
        units = len(value.encode("utf-16-le")) // 2
        if units > 127 or len(raw) > 127:
            raise ValueError("synthetic binary XML string exceeds short length encoding")
        offsets.append(len(strings_data))
        strings_data.extend((units, len(raw)))
        strings_data.extend(raw)
        strings_data.append(0)
    pool_data = (
        struct.pack("<IIIII", len(values), 0, 0x100, 28 + len(offsets) * 4, 0)
        + b"".join(struct.pack("<I", off) for off in offsets)
        + strings_data
    )
    pool = struct.pack("<HHI", 1, 28, len(pool_data) + 8) + pool_data
    node_start = struct.pack("<II", 1, 0xffffffff) + struct.pack(
        "<IIHHHHHH", 0xffffffff, 0, 20, 20, 0, 0, 0, 0
    )
    node_end = struct.pack("<II", 2, 0xffffffff) + struct.pack("<II", 0xffffffff, 0)
    start = struct.pack("<HHI", 0x0102, 16, len(node_start) + 8) + node_start
    end = struct.pack("<HHI", 0x0103, 16, len(node_end) + 8) + node_end
    resource_map = struct.pack("<HHII", 0x0180, 8, 12, 0x01010003) if include_resource_map else b""
    children = pool + resource_map + start + end
    return struct.pack("<HHI", 3, 8, len(children) + 8) + children

for filename, values in {
    "binary-valid-unreferenced": ["manifest", "other_unrelated"],
    "binary-valid-class-alias": ["manifest", "com.test.A"],
    "binary-valid-relative-alias": ["manifest", ".A"],
}.items():
    with zipfile.ZipFile(directory / f"{filename}.apk", "w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("AndroidManifest.xml", binary_manifest(values))
        output.writestr("classes.dex", first)
        output.writestr("classes2.dex", second)

# Corrupt only the raw compressed stream (not ZIP CRC or length metadata).
corrupted = bytearray((directory / "compressed-dex.apk").read_bytes())
with zipfile.ZipFile(directory / "compressed-dex.apk") as compressed_apk:
    entry = compressed_apk.getinfo("classes.dex")
    offset = entry.header_offset
    local_name_len = int.from_bytes(corrupted[offset + 26:offset + 28], "little")
    local_extra_len = int.from_bytes(corrupted[offset + 28:offset + 30], "little")
    payload_offset = offset + 30 + local_name_len + local_extra_len
    corrupted[payload_offset] ^= 0xff
(directory / "corrupt-deflate.apk").write_bytes(corrupted)

# Reject an inflated-size claim before allocating memory for a ZIP bomb.
# Patch the *DEX* local header AND corresponding central record; changing the
# first ZIP record only changes the manifest and does not test DEX limits.
oversized = bytearray((directory / "compressed-dex.apk").read_bytes())
with zipfile.ZipFile(directory / "compressed-dex.apk") as compressed_apk:
    dex_entry = compressed_apk.getinfo("classes.dex")
    oversized[dex_entry.header_offset + 22:dex_entry.header_offset + 26] = (65 * 1024 * 1024).to_bytes(4, "little")
central_offset = 0
found = False
while True:
    central_offset = oversized.find(b"PK\x01\x02", central_offset)
    if central_offset < 0:
        break
    name_len = int.from_bytes(oversized[central_offset + 28:central_offset + 30], "little")
    name = oversized[central_offset + 46:central_offset + 46 + name_len]
    if name == b"classes.dex":
        oversized[central_offset + 24:central_offset + 28] = (65 * 1024 * 1024).to_bytes(4, "little")
        found = True
        break
    central_offset += 4
if not found:
    raise RuntimeError("DEX central record missing from oversized fixture")
(directory / "oversized-deflate.apk").write_bytes(oversized)

with zipfile.ZipFile(directory / "duplicate-class.apk", "w", compression=zipfile.ZIP_STORED) as output:
    output.writestr("AndroidManifest.xml", manifest)
    output.writestr("classes.dex", first)
    output.writestr("classes2.dex", first)

# Corrupt the central-directory CRC of classes.dex without mutating the
# payload, to prove that the production diagnostic validates real bytes.
damaged = bytearray((directory / "valid.apk").read_bytes())
offset = 0
found = False
while True:
    offset = damaged.find(b"PK\x01\x02", offset)
    if offset < 0:
        break
    name_len = int.from_bytes(damaged[offset + 28:offset + 30], "little")
    name = damaged[offset + 46:offset + 46 + name_len]
    if name == b"classes.dex":
        damaged[offset + 16] ^= 0x01
        found = True
        break
    offset += 4
if not found:
    raise RuntimeError("synthetic central-directory classes.dex record missing")
(directory / "crc-mismatch.apk").write_bytes(damaged)

print("Phase O.1 stored/deflated valid, corrupt DEFLATE, oversize, malformed, duplicate and bad-CRC fixtures created.")
