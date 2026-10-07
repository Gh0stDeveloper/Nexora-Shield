#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ACTIVE = ROOT / "schemas/nexora-shield.schema.json"
FROZEN = ROOT / "schemas/nexora-shield.schema.v1.json"


def main() -> int:
    active = ACTIVE.read_bytes()
    frozen = FROZEN.read_bytes()
    if active != frozen:
        raise SystemExit(
            "schema lock failed: active schema differs from frozen v1 snapshot; "
            "a schema bump + migration is required instead of mutating schema 1"
        )

    parsed = json.loads(active)
    if parsed.get("properties", {}).get("schema", {}).get("const") != 1:
        raise SystemExit("schema lock failed: schema const must remain 1")

    print(f"Schema lock: OK | bytes={len(active)} | schema=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
