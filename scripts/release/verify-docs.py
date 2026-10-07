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
    ]
    found = [marker for marker in stale if marker in readme]
    if found:
        raise SystemExit("documentation audit failed: stale README markers: " + repr(found))

    roadmap = (ROOT / "docs/ROADMAP.md").read_text()
    for phase in ["Fase L", "Fase M", "Fase N"]:
        if phase not in roadmap:
            raise SystemExit(f"documentation audit failed: roadmap missing {phase}")

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
