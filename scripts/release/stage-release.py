#!/usr/bin/env python3
from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def workspace_version() -> str:
    text = (ROOT / "Cargo.toml").read_text()
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    if not match:
        raise SystemExit("release staging failed: workspace version not found")
    return match.group(1)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: stage-release.py <Linux|macOS|Windows>")

    runner = sys.argv[1]
    key = runner.lower()
    if key not in {"linux", "macos", "windows"}:
        raise SystemExit(f"release staging failed: unsupported runner '{runner}'")

    version = workspace_version()
    destination = ROOT / "build" / "release" / "stage" / key
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)

    cli_name = "nexora-shield.exe" if key == "windows" else "nexora-shield"
    cli = ROOT / "target" / "release" / cli_name
    if not cli.is_file():
        raise SystemExit(f"release staging failed: CLI not found at {cli}")
    cli_suffix = ".exe" if key == "windows" else ""
    shutil.copy2(cli, destination / f"nexora-shield-{version}-{key}{cli_suffix}")

    expected_suffix = {"linux": ".deb", "macos": ".dmg", "windows": ".msi"}[key]
    compose_root = ROOT / "studio" / "build" / "compose" / "binaries"
    packages = sorted(
        path for path in compose_root.rglob(f"*{expected_suffix}") if path.is_file()
    )
    if not packages:
        raise SystemExit(
            f"release staging failed: no Shield Studio {expected_suffix} package found"
        )
    if len(packages) != 1:
        raise SystemExit(
            "release staging failed: expected exactly one Studio package, found "
            + ", ".join(str(path) for path in packages)
        )

    shutil.copy2(
        packages[0],
        destination / f"nexora-shield-studio-{version}-{key}{expected_suffix}",
    )
    print(f"Release staging: OK | platform={key} | files=2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
