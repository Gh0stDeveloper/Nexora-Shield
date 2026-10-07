#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def fail(message: str) -> None:
    raise SystemExit(f"API freeze verification failed: {message}")


def main() -> int:
    contract = json.loads((ROOT / "release/api-surface-v1.json").read_text())
    if contract.get("contractVersion") != 1:
        fail("contractVersion must be 1")
    if contract.get("configSchema") != 1:
        fail("configSchema must be 1")
    if contract.get("minimumAndroidSdk") != 24:
        fail("minimumAndroidSdk must be 24")
    if contract.get("gradlePluginId") != "dev.nexora.shield":
        fail("Gradle plugin id changed")

    cli = (ROOT / "crates/shield-cli/src/main.rs").read_text()
    commands = contract.get("cliCommands", [])
    if not commands or len(commands) != len(set(commands)):
        fail("CLI commands must be non-empty and unique")
    for command in commands:
        if not re.search(rf'"{re.escape(command)}"\s*=>', cli):
            fail(f"stable CLI command '{command}' is not dispatched by shield-cli")

    core = (ROOT / "crates/shield-core/src/lib.rs").read_text()
    if "pub const CONFIG_SCHEMA_VERSION: u32 = 1;" not in core:
        fail("shield-core CONFIG_SCHEMA_VERSION no longer equals 1")

    plugin = (ROOT / "gradle-plugin/build.gradle.kts").read_text()
    if 'id = "dev.nexora.shield"' not in plugin:
        fail("Gradle plugin id no longer matches frozen contract")

    schema = json.loads((ROOT / "schemas/nexora-shield.schema.json").read_text())
    if schema.get("properties", {}).get("schema", {}).get("const") != 1:
        fail("active JSON schema no longer declares schema 1")

    required_profiles = {"standard", "hardened", "maximum"}
    if set(contract.get("protectionProfiles", [])) != required_profiles:
        fail("protection profile contract changed")

    print(f"API freeze: OK | commands={len(commands)} | schema=1 | minSdk=24")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
