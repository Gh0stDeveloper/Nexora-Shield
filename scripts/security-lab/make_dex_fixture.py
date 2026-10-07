#!/usr/bin/env python3
"""Create the minimal valid DEX fixture used by the defensive Security Lab."""

from __future__ import annotations

import hashlib
import struct
import sys
import zlib
from pathlib import Path

DEX_HEADER_SIZE = 0x70
DEX_ENDIAN_CONSTANT = 0x12345678


def uleb(value: int) -> bytes:
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        output.append(byte)
        if not value:
            return bytes(output)


def put_u16(buffer: bytearray, offset: int, value: int) -> None:
    buffer[offset : offset + 2] = struct.pack("<H", value)


def put_u32(buffer: bytearray, offset: int, value: int) -> None:
    buffer[offset : offset + 4] = struct.pack("<I", value)


def build_fixture() -> bytes:
    strings = [
        "Ldev/nexora/securitylab/Main;",
        "Ljava/lang/Object;",
        "V",
        "run",
        "Main.java",
    ]
    string_ids_off = DEX_HEADER_SIZE
    type_ids_off = string_ids_off + len(strings) * 4
    proto_ids_off = type_ids_off + 3 * 4
    method_ids_off = proto_ids_off + 12
    class_defs_off = method_ids_off + 8
    data_off = class_defs_off + 32

    data = bytearray(data_off)
    string_offsets: list[int] = []
    for value in strings:
        string_offsets.append(len(data))
        data += uleb(len(value.encode("utf-16-le")) // 2)
        data += value.encode("ascii")
        data.append(0)

    while len(data) % 4:
        data.append(0)

    code_off = len(data)
    data += struct.pack("<HHHHIIH", 0, 0, 0, 0, 0, 1, 0x000E)
    class_data_off = len(data)
    data += uleb(0) + uleb(0) + uleb(1) + uleb(0)
    data += uleb(0) + uleb(0x0009) + uleb(code_off)

    file_size = len(data)
    data[0:8] = b"dex\n035\0"
    put_u32(data, 32, file_size)
    put_u32(data, 36, DEX_HEADER_SIZE)
    put_u32(data, 40, DEX_ENDIAN_CONSTANT)
    put_u32(data, 56, len(strings))
    put_u32(data, 60, string_ids_off)
    put_u32(data, 64, 3)
    put_u32(data, 68, type_ids_off)
    put_u32(data, 72, 1)
    put_u32(data, 76, proto_ids_off)
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
    put_u32(data, class_defs_off + 16, 4)
    put_u32(data, class_defs_off + 24, class_data_off)

    data[12:32] = hashlib.sha1(data[32:]).digest()
    put_u32(data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)
    return bytes(data)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_dex_fixture.py <output.dex>", file=sys.stderr)
        return 2
    output = Path(sys.argv[1])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(build_fixture())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
