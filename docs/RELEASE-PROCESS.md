# Nexora Shield release process

> **Stable release freeze:** a strict post-Phase-N audit opened [Phase O](PHASE-O.md). The stable `v1.0.0` tag MUST NOT be created while Phase O remains open. Phase N qualification evidence is retained as historical evidence but is not sufficient for final production approval.

## Release channels

- Release candidate: `v1.0.0-rc.N`
- Stable: `v1.0.0`

Stable cannot bypass RC-equivalent qualification.

## RC qualification

The 1.0 RC line must satisfy:

1. Phase M, L, K and repository regressions;
2. Phase N release contracts;
3. API/schema locks and migrations;
4. SBOM/provenance;
5. retrace validation;
6. security/performance/compatibility reviews;
7. independent external assessment.

For the 1.0 line, Phase N #54 (run `37686651703`) is the retained RC qualification evidence and passed 9/9 jobs.

Publishing an RC tag is a distribution step. It does not replace qualification, and stable cannot be promoted from code that lacks retained RC-equivalent evidence.

## Human feedback

Human feedback is collected through the [external assessment and feedback guide](RC-FEEDBACK.md) and GitHub issue form.

Human findings are supplementary to the required independent assessment. A recorded blocking external finding always blocks stable.

## Stable qualification

Before `v1.0.0`:

1. the configured independent external assessment must be recorded;
2. blocking external findings must be zero;
3. N.10 representative Android performance evidence must be complete;
4. all Phase N stable gates must pass;
5. versions must be exactly `1.0.0`;
6. changelog/release notes must reflect the stable promotion;
7. the stable tag must be created only from the validated `main` commit.

The current release workflow enforces the Phase N-era prerequisites above. Phase O adds stricter prerequisites that must be implemented before stable publication, including exact tag-to-main ancestry, exact-commit required-check validation, a blocking CodeQL/SARIF findings gate, verified repository governance, license readiness and final O.14 approval. Until those controls exist and pass, stable publication remains blocked.

## Stable publication

Stable publication now additionally requires **Phase O O.14 final production audit approval** and completion of O.15 pre-publication checks.

The `v1.0.0` tag triggers `.github/workflows/release.yml`, but the tag must not be created until Phase O is closed.

The workflow:

- validates stable metadata and synchronized version;
- builds CLI + Shield Studio on Linux/macOS/Windows;
- stages deterministic platform artifacts;
- generates SHA-256 checksums;
- generates CycloneDX SBOM and local provenance;
- emits GitHub build-provenance attestations;
- publishes the stable GitHub Release.

## Rollback

A compromised or materially broken release must not be silently replaced. Publish a new version and clearly mark/revoke the affected release. Build/release evidence remains immutable.


## Final 1.0 qualification evidence

The stable source line was validated before merge at:

- head: `ce92ea791dc860a505658a67be1b9250105a834a`;
- Phase N #86 (`37691051042`): 9/9 jobs successful;
- CI #1156: successful;
- Phase M #86, Phase L #92 and Phase K #107: successful;
- zero failed jobs.

This Phase N evidence remains valid for the controls it tested. A post-N production audit subsequently identified release blockers outside that original qualification scope. Therefore **do not create `v1.0.0` from this N-era evidence alone**.

The stable tag may be created only after Phase O closes and O.14 approves the exact final `main` commit. See [Production Readiness Audit](PRODUCTION-READINESS-AUDIT.md) and [Phase O checklist](PHASE-O-CHECKLIST.md).
