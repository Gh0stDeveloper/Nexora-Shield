# Nexora Shield release process

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

The release workflow fails closed if any stable prerequisite is missing.

## Stable publication

The `v1.0.0` tag triggers `.github/workflows/release.yml`.

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

After this head is merged, the `v1.0.0` tag must be created from the resulting validated `main` commit. The tag triggers the attested release workflow; it must not be created from the feature branch.
