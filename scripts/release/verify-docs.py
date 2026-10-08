#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REQUIRED = [
    "README.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "docs/ROADMAP.md",
    "docs/CONFIGURATION.md",
    "docs/THREAT-MODEL.md",
    "docs/SECURITY-DESIGN.md",
    "docs/TESTING.md",
    "docs/PHASE-M.md",
    "docs/PHASE-N.md",
    "docs/PHASE-O.md",
    "docs/PHASE-O-CHECKLIST.md",
    "docs/PHASE-O0-BASELINE.md",
    "docs/PHASE-O-ACCEPTED-RISK.md",
    "docs/PRODUCTION-READINESS-AUDIT.md",
    "docs/API-STABILITY.md",
    "docs/RELEASE-PROCESS.md",
    "docs/PHASE-N-SECURITY-REVIEW.md",
    "docs/PHASE-N-PERFORMANCE-REVIEW.md",
    "docs/PHASE-N-COMPATIBILITY-REVIEW.md",
    "docs/RC-FEEDBACK.md",
]


def main() -> int:
    missing = [path for path in REQUIRED if not (ROOT / path).is_file()]
    if missing:
        raise SystemExit("documentation audit failed: missing " + ", ".join(missing))

    readme = (ROOT / "README.md").read_text()
    stale = [
        "Phase_J-Gradle_Plugin_complete",
        "Next milestone | **Phase K",
        "current stable implementation covers the protection pipeline through **Phase J",
        "Future roadmap components such as Native Shield",
        "| **F** | Native Shield | Next |",
        "| **N** | Production hardening / 1.0 | Planned |",
        "validated for stable publication.",
        "Stable 1.0 | **Qualified",
    ]
    found = [marker for marker in stale if marker in readme]
    if found:
        raise SystemExit("documentation audit failed: stale README markers: " + repr(found))

    roadmap = (ROOT / "docs/ROADMAP.md").read_text()
    for phase in ["Fase L", "Fase M", "Fase N", "Fase O"]:
        if phase not in roadmap:
            raise SystemExit(f"documentation audit failed: roadmap missing {phase}")

    required_release_markers = {
        "README.md": ["Phase O", "NO-GO until Phase O closes"],
        "docs/RELEASE-PROCESS.md": ["Stable release freeze", "Phase O"],
        "docs/PHASE-O.md": ["OPEN — RELEASE BLOCKING", "NO-GO for public stable"],
        "docs/PHASE-O-CHECKLIST.md": ["Current decision: **NO-GO for public stable v1.0.0**"],
        "docs/PHASE-O0-BASELINE.md": ["stable publication: **BLOCKED**", "18"],
        "docs/PHASE-O-ACCEPTED-RISK.md": ["P0", "P1", "P2"],
        "docs/PRODUCTION-READINESS-AUDIT.md": ["NO-GO for public stable"],
    }
    for path, markers in required_release_markers.items():
        content = (ROOT / path).read_text()
        missing_markers = [marker for marker in markers if marker not in content]
        if missing_markers:
            raise SystemExit(
                f"documentation audit failed: {path} missing release markers {missing_markers!r}"
            )

    # Validate local markdown links that resolve to explicit file paths.
    pattern = re.compile(r"\[[^\]]+\]\(([^)#]+)(?:#[^)]+)?\)")
    broken: list[str] = []
    for doc in [ROOT / "README.md", ROOT / "docs/RELEASE-PROCESS.md", ROOT / "docs/API-STABILITY.md"]:
        for target in pattern.findall(doc.read_text()):
            if "://" in target or target.startswith("mailto:"):
                continue
            candidate = (doc.parent / target).resolve()
            try:
                candidate.relative_to(ROOT.resolve())
            except ValueError:
                broken.append(f"{doc.relative_to(ROOT)} -> {target}")
                continue
            if not candidate.exists():
                broken.append(f"{doc.relative_to(ROOT)} -> {target}")
    if broken:
        raise SystemExit("documentation audit failed: broken local links: " + ", ".join(broken))

    print(f"Documentation audit: OK | required={len(REQUIRED)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
