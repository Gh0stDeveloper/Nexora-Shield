#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: write-checksums.py <artifact-dir> <output>")

    root = Path(sys.argv[1])
    output = Path(sys.argv[2])
    files = sorted(path for path in root.rglob("*") if path.is_file())
    if not files:
        raise SystemExit("checksum generation failed: no artifacts found")

    lines = [f"{sha256(path)}  {path.relative_to(root).as_posix()}" for path in files]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n")
    print(f"Checksums: OK | files={len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
