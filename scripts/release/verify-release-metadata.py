#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load(name: str) -> dict:
    return json.loads((ROOT / "release" / name).read_text())


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"rc", "stable"}:
        raise SystemExit("usage: verify-release-metadata.py <rc|stable>")
    channel = sys.argv[1]

    policy = load("qualification-policy.json")
    feedback = load("feedback-status.json")
    security = load("security-review.json")
    performance = load("performance-review.json")
    compatibility = load("compatibility-matrix.json")

    if policy.get("schema") != 1:
        raise SystemExit("release metadata failed: qualification schema must be 1")
    if security.get("criticalFindingsOpen") != 0 or security.get("blockingFindingsOpen") != 0:
        raise SystemExit("release metadata failed: blocking security finding remains open")
    if security.get("highFindingsOpen") != 0:
        raise SystemExit("release metadata failed: high security finding remains open")
    if performance.get("rcReviewPassed") is not True:
        raise SystemExit("release metadata failed: RC performance review is not complete")
    if compatibility.get("minimumAndroidSdk") != 24:
        raise SystemExit("release metadata failed: compatibility matrix minSdk drifted")
    if compatibility.get("rustMsrv") != "1.81":
        raise SystemExit("release metadata failed: compatibility matrix MSRV drifted")

    if channel == "stable":
        if performance.get("stableDeviceMeasurementsComplete") is not True:
            raise SystemExit(
                "stable release blocked: representative device performance measurements are incomplete"
            )
        minimum = int(policy.get("minimumExternalReviewers", 1))
        if int(feedback.get("externalReviewers", 0)) < minimum:
            raise SystemExit(
                f"stable release blocked: external reviewers={feedback.get('externalReviewers', 0)} required={minimum}"
            )
        if int(feedback.get("blockingFindingsOpen", 0)) != 0:
            raise SystemExit("stable release blocked: external feedback has blocking findings")

    print(f"Release metadata: OK | channel={channel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
