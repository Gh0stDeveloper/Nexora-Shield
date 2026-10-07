#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"
ALLOWED_ACTION_OWNERS = {"actions", "dtolnay", "gradle", "Swatinem", "taiki-e", "github"}
FORBIDDEN = {
    "pull_request_target": "pull_request_target is forbidden for release hardening",
    "@main": "mutable action ref @main is forbidden",
    "@master": "mutable action ref @master is forbidden",
    "write-all": "permissions: write-all is forbidden",
}


def main() -> int:
    errors: list[str] = []
    workflows = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    if not workflows:
        raise SystemExit("supply-chain verification failed: no workflows found")

    uses_re = re.compile(r"^\s*-?\s*uses:\s*([^\s]+)", re.MULTILINE)
    pipe_shell_re = re.compile(r"\b(?:curl|wget)\b[^\n]*\|\s*(?:ba)?sh\b")

    for path in workflows:
        text = path.read_text()
        relative = path.relative_to(ROOT)
        if "permissions:" not in text:
            errors.append(f"{relative}: explicit permissions block is required")
        for needle, message in FORBIDDEN.items():
            if needle in text:
                errors.append(f"{relative}: {message}")
        if pipe_shell_re.search(text):
            errors.append(f"{relative}: network-to-shell execution is forbidden")

        for action in uses_re.findall(text):
            if action.startswith("./"):
                continue
            repo = action.split("@", 1)[0]
            owner = repo.split("/", 1)[0]
            if owner not in ALLOWED_ACTION_OWNERS:
                errors.append(f"{relative}: action owner '{owner}' is not allowlisted")

        if path.name != "release.yml" and "contents: write" in text:
            errors.append(f"{relative}: contents: write is reserved for release.yml")
        if path.name != "release.yml" and "id-token: write" in text:
            errors.append(f"{relative}: id-token: write is reserved for release.yml")

    if errors:
        raise SystemExit("supply-chain verification failed:\n- " + "\n- ".join(errors))

    print(f"Supply-chain policy: OK | workflows={len(workflows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
