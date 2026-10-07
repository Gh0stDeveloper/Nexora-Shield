#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


def component(package: dict) -> dict:
    name = package["name"]
    version = package["version"]
    item = {
        "type": "library",
        "bom-ref": f"pkg:cargo/{name}@{version}",
        "name": name,
        "version": version,
        "purl": f"pkg:cargo/{name}@{version}",
    }
    if package.get("license"):
        item["licenses"] = [{"license": {"id": package["license"]}}]
    return item


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: generate-sbom.py <cargo-metadata.json> <output.cdx.json>")

    metadata_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    metadata = json.loads(metadata_path.read_text())
    packages = sorted(
        metadata.get("packages", []),
        key=lambda value: (value["name"], value["version"], value.get("source") or ""),
    )
    workspace = set(metadata.get("workspace_members", []))
    roots = [package for package in packages if package.get("id") in workspace]
    primary = next(
        (package for package in roots if package["name"] == "nexora-shield"),
        roots[0] if roots else None,
    )
    if primary is None:
        raise SystemExit("SBOM generation failed: workspace package not found")

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": f"pkg:cargo/{primary['name']}@{primary['version']}",
                "name": primary["name"],
                "version": primary["version"],
            }
        },
        "components": [component(package) for package in packages],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n")
    print(f"SBOM: OK | components={len(packages)} | output={output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
