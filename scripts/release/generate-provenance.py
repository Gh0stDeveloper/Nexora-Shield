#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit(
            "usage: generate-provenance.py <output.json> <artifact> [artifact ...]"
        )

    output = Path(sys.argv[1])
    artifacts = [Path(value) for value in sys.argv[2:]]
    missing = [str(path) for path in artifacts if not path.is_file()]
    if missing:
        raise SystemExit("provenance generation failed: missing " + ", ".join(missing))

    subjects = [
        {"name": path.name, "digest": {"sha256": digest(path)}} for path in artifacts
    ]
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/Gh0stDeveloper/Nexora-Shield/phase-n-release/v1",
                "externalParameters": {
                    "gitRef": os.environ.get("GITHUB_REF", "local"),
                    "gitSha": os.environ.get("GITHUB_SHA", "local"),
                },
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/Gh0stDeveloper/Nexora-Shield",
                        "digest": {"gitCommit": os.environ.get("GITHUB_SHA", "local")},
                    }
                ],
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/actions/runner"
                    if os.environ.get("GITHUB_ACTIONS") == "true"
                    else "local"
                }
            },
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(statement, indent=2, sort_keys=True) + "\n")
    print(f"Provenance manifest: OK | subjects={len(subjects)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
