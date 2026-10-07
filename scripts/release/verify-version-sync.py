#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def capture(path: Path, pattern: str, label: str) -> str:
    match = re.search(pattern, path.read_text(), re.MULTILINE)
    if not match:
        raise SystemExit(f"version sync failed: could not read {label} from {path}")
    return match.group(1)


def main() -> int:
    expected = sys.argv[1] if len(sys.argv) == 2 else "1.0.0-rc.1"
    cargo = capture(
        ROOT / "Cargo.toml",
        r'(?m)^version\s*=\s*"([^"]+)"',
        "workspace version",
    )
    plugin = capture(
        ROOT / "gradle-plugin/build.gradle.kts",
        r'(?m)^version\s*=\s*"([^"]+)"',
        "Gradle Plugin version",
    )
    studio = capture(
        ROOT / "studio/build.gradle.kts",
        r'(?m)^version\s*=\s*"([^"]+)"',
        "Studio version",
    )

    values = {"Cargo": cargo, "Gradle Plugin": plugin, "Studio": studio}
    drift = {name: value for name, value in values.items() if value != expected}
    if drift:
        raise SystemExit(f"version sync failed: expected {expected}, got {drift}")

    lock = (ROOT / "Cargo.lock").read_text()
    blocks = lock.split("[[package]]")
    bad: list[str] = []
    for block in blocks:
        name_match = re.search(r'\bname = "(nexora-shield[^"]*)"', block)
        if not name_match:
            continue
        version_match = re.search(r'\bversion = "([^"]+)"', block)
        if not version_match or version_match.group(1) != expected:
            bad.append(name_match.group(1))
    if bad:
        raise SystemExit("version sync failed: Cargo.lock drift for " + ", ".join(bad))

    print(f"Version sync: OK | version={expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
