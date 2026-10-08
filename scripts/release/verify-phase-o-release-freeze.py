#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATUS_PATH = ROOT / "release" / "phase-o-status.json"
FINDINGS_PATH = ROOT / "release" / "phase-o-findings.json"
RISKS_PATH = ROOT / "release" / "phase-o-accepted-risks.json"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"

EXPECTED_PHASE_O_BASELINE = "d8e436d3d49efad417f501e229d8cd57b0e86b95"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VALID_SEVERITIES = {"P0", "P1", "P2"}
VALID_STATUSES = {"open", "closed", "accepted"}


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except FileNotFoundError as error:
        raise SystemExit(f"Phase O validation failed: missing {path.relative_to(ROOT)}") from error
    except json.JSONDecodeError as error:
        raise SystemExit(
            f"Phase O validation failed: invalid JSON in {path.relative_to(ROOT)}: {error}"
        ) from error
    if not isinstance(value, dict):
        raise SystemExit(
            f"Phase O validation failed: {path.relative_to(ROOT)} must contain a JSON object"
        )
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"Phase O validation failed: {message}")


def validate_status(status: dict) -> None:
    require(status.get("schema") == 1, "phase-o-status schema must be 1")
    require(status.get("phase") == "O", "phase-o-status phase must be O")
    require(status.get("status") in {"open", "closed"}, "Phase O status must be open or closed")
    require(
        status.get("releaseDecision") in {"no-go", "go"},
        "releaseDecision must be no-go or go",
    )
    require(status.get("stableTag") == "v1.0.0", "stableTag must be v1.0.0")
    require(status.get("sourceVersion") == "1.0.0", "sourceVersion must be 1.0.0")

    discovery = status.get("auditDiscoveryBaseline")
    baseline = status.get("phaseOBaseline")
    require(isinstance(discovery, dict), "auditDiscoveryBaseline is required")
    require(isinstance(baseline, dict), "phaseOBaseline is required")
    for label, record in (
        ("auditDiscoveryBaseline", discovery),
        ("phaseOBaseline", baseline),
    ):
        require(record.get("branch") == "main", f"{label}.branch must be main")
        sha = record.get("sha")
        require(isinstance(sha, str) and SHA_RE.fullmatch(sha), f"{label}.sha must be a full lowercase SHA")

    require(
        baseline["sha"] == EXPECTED_PHASE_O_BASELINE,
        "Phase O execution baseline changed unexpectedly",
    )

    historical = status.get("phaseNHistoricalEvidence")
    require(isinstance(historical, dict), "phaseNHistoricalEvidence is required")
    require(historical.get("preserved") is True, "Phase N historical evidence must be preserved")
    merge_commit = historical.get("mergeCommit")
    require(
        isinstance(merge_commit, str) and SHA_RE.fullmatch(merge_commit),
        "Phase N historical mergeCommit must be a full SHA",
    )

    o0 = status.get("o0")
    require(isinstance(o0, dict), "o0 metadata is required")
    require(o0.get("owner") == "repository-maintainers", "O.0 owner must be repository-maintainers")
    require(o0.get("finalApprovalPhase") == "O.14", "final approval must remain O.14")
    require(o0.get("publicationPhase") == "O.15", "publication phase must remain O.15")


def validate_findings(findings_doc: dict) -> tuple[list[dict], dict[str, int]]:
    require(findings_doc.get("schema") == 1, "phase-o-findings schema must be 1")
    require(
        findings_doc.get("baselineSha") == EXPECTED_PHASE_O_BASELINE,
        "finding inventory baseline does not match Phase O baseline",
    )
    findings = findings_doc.get("findings")
    require(isinstance(findings, list), "findings must be a list")
    require(len(findings) == 18, "initial Phase O inventory must retain all 18 audited findings")

    seen: set[str] = set()
    counts = {"P0": 0, "P1": 0, "P2": 0}
    for finding in findings:
        require(isinstance(finding, dict), "every finding must be an object")
        finding_id = finding.get("id")
        severity = finding.get("severity")
        status = finding.get("status")
        require(isinstance(finding_id, str) and finding_id, "finding id is required")
        require(finding_id not in seen, f"duplicate finding id: {finding_id}")
        seen.add(finding_id)
        require(severity in VALID_SEVERITIES, f"{finding_id}: invalid severity")
        require(status in VALID_STATUSES, f"{finding_id}: invalid status")
        require(isinstance(finding.get("releaseBlocking"), bool), f"{finding_id}: releaseBlocking must be bool")
        require(isinstance(finding.get("releaseRequired"), bool), f"{finding_id}: releaseRequired must be bool")
        require(
            isinstance(finding.get("remediationPhase"), str)
            and re.fullmatch(r"O\.(?:[1-9]|1[0-5])", finding["remediationPhase"]),
            f"{finding_id}: invalid remediationPhase",
        )
        require(
            isinstance(finding.get("title"), str) and finding["title"].strip(),
            f"{finding_id}: title is required",
        )

        if severity in {"P0", "P1"}:
            require(finding["releaseBlocking"] is True, f"{finding_id}: P0/P1 must block release")
            require(finding["releaseRequired"] is True, f"{finding_id}: P0/P1 must be release-required")
            require(status != "accepted", f"{finding_id}: P0/P1 cannot be accepted")

        counts[severity] += 1

    require(counts == {"P0": 8, "P1": 8, "P2": 2}, f"unexpected severity counts: {counts}")
    return findings, counts


def validate_risks(risks_doc: dict, findings: list[dict]) -> None:
    require(risks_doc.get("schema") == 1, "phase-o-accepted-risks schema must be 1")
    policy = risks_doc.get("policy")
    require(isinstance(policy, dict), "accepted-risk policy object is required")
    require(policy.get("allowedSeverities") == ["P2"], "only P2 may be eligible for accepted risk")
    require(
        set(policy.get("prohibitedSeverities", [])) == {"P0", "P1"},
        "P0/P1 must be prohibited from accepted risk",
    )
    require(
        policy.get("releaseRequiredFindingsMayBeAccepted") is False,
        "release-required findings may not be accepted",
    )

    required_fields = policy.get("requiredFields")
    require(isinstance(required_fields, list) and required_fields, "accepted-risk requiredFields are required")

    by_id = {finding["id"]: finding for finding in findings}
    accepted = risks_doc.get("acceptedRisks")
    require(isinstance(accepted, list), "acceptedRisks must be a list")

    seen: set[str] = set()
    for entry in accepted:
        require(isinstance(entry, dict), "accepted risk entry must be an object")
        finding_id = entry.get("findingId")
        require(finding_id in by_id, f"accepted risk references unknown finding {finding_id!r}")
        require(finding_id not in seen, f"duplicate accepted risk for {finding_id}")
        seen.add(finding_id)
        finding = by_id[finding_id]
        require(finding["severity"] == "P2", f"{finding_id}: only P2 can be accepted")
        require(finding["releaseRequired"] is False, f"{finding_id}: release-required finding cannot be accepted")
        require(finding["status"] == "accepted", f"{finding_id}: finding status must be accepted")
        for field in required_fields:
            require(field in entry and entry[field], f"{finding_id}: accepted risk missing {field}")


def validate_release_decision(status: dict, findings: list[dict]) -> None:
    unresolved_release_blockers = [
        finding
        for finding in findings
        if finding["status"] == "open"
        and (finding["releaseBlocking"] or finding["releaseRequired"])
    ]

    if status["status"] == "open":
        require(status.get("releaseDecision") == "no-go", "open Phase O must remain NO-GO")
        require(status.get("stablePublicationBlocked") is True, "open Phase O must block stable publication")
        require(unresolved_release_blockers, "open Phase O must not claim zero release blockers")
    else:
        require(not unresolved_release_blockers, "closed Phase O cannot retain release blockers")
        require(status.get("releaseDecision") == "go", "closed Phase O must explicitly record GO")
        require(status.get("stablePublicationBlocked") is False, "closed Phase O must remove stable freeze")


def validate_release_workflow() -> None:
    content = RELEASE_WORKFLOW.read_text()
    marker = 'python scripts/release/verify-phase-o-release-freeze.py --channel "$NEXORA_RELEASE_CHANNEL"'
    require(marker in content, "release workflow does not enforce the Phase O freeze")


def validate_all() -> tuple[dict, list[dict], dict[str, int]]:
    status = load_json(STATUS_PATH)
    findings_doc = load_json(FINDINGS_PATH)
    risks_doc = load_json(RISKS_PATH)
    validate_status(status)
    findings, counts = validate_findings(findings_doc)
    validate_risks(risks_doc, findings)
    validate_release_decision(status, findings)
    validate_release_workflow()
    return status, findings, counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel", choices=("rc", "stable"))
    args = parser.parse_args()

    status, findings, counts = validate_all()
    open_blockers = sum(
        1
        for finding in findings
        if finding["status"] == "open"
        and (finding["releaseBlocking"] or finding["releaseRequired"])
    )

    if args.channel == "stable":
        if status["stablePublicationBlocked"]:
            print(
                "Phase O release freeze: BLOCKED | "
                f"status={status['status']} decision={status['releaseDecision']} "
                f"open_release_blockers={open_blockers}",
                file=sys.stderr,
            )
            return 2
        print("Phase O stable release gate: OPEN")
        return 0

    if args.channel == "rc":
        print(
            "Phase O RC gate: allowed for controlled testing | "
            f"stable_blocked={str(status['stablePublicationBlocked']).lower()}"
        )
        return 0

    print(
        "Phase O baseline: OK | "
        f"status={status['status']} decision={status['releaseDecision']} "
        f"P0={counts['P0']} P1={counts['P1']} P2={counts['P2']} "
        f"open_release_blockers={open_blockers}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
