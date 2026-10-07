#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/release.yml"

REQUIRED = [
    '"v1.0.0-rc.*"',
    '"v1.0.0"',
    "contents: write",
    "id-token: write",
    "attestations: write",
    "actions/attest-build-provenance@v3",
    "write-checksums.py",
    "generate-provenance.py",
    "generate-sbom.py",
    "verify-release-metadata.py",
    "feedback-validate",
    "gh release create",
    "--prerelease",
]


def main() -> int:
    text = WORKFLOW.read_text()
    missing = [needle for needle in REQUIRED if needle not in text]
    if missing:
        raise SystemExit(
            "release workflow verification failed: missing " + ", ".join(missing)
        )
    if "workflow_dispatch:" in text:
        raise SystemExit(
            "release workflow verification failed: direct manual dispatch is disabled; releases must originate from qualified tags"
        )
    print("Release workflow contract: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
