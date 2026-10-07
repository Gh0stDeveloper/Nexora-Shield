# Nexora Shield release process

## Release channels

- Release candidate: `v1.0.0-rc.N`
- Stable: `v1.0.0`

Stable cannot be used as a shortcut around the RC process.

## RC qualification

Before creating an RC tag:

1. merge the release candidate code into `main`;
2. confirm Phase M, Phase L, Phase K and repository CI are green;
3. confirm Phase N is green;
4. confirm `scripts/release/verify-version-sync.py 1.0.0-rc.1`;
5. confirm API/schema locks;
6. generate SBOM and provenance;
7. confirm internal security/performance/compatibility reviews;
8. create `v1.0.0-rc.1`.

The release workflow builds platform artifacts, generates checksums and provenance, creates GitHub attestations and publishes the RC as a prerelease.

## External feedback

RC users report feedback through the [RC feedback guide](RC-FEEDBACK.md) and GitHub issue form.

Accepted external review evidence is recorded in `../release/feedback-status.json`. Do not increment reviewer counts for internal CI or self-review.

## Stable qualification

Before `v1.0.0`:

1. at least the configured number of real external reviewers must be recorded;
2. blocking external findings must be zero;
3. representative-device performance measurements must be complete;
4. all Phase N stable gates must pass;
5. versions must be changed exactly to `1.0.0`;
6. changelog/release notes must reflect the final RC delta;
7. create the stable tag only from the validated `main` commit.

The release workflow fails closed if stable prerequisites are not satisfied.

## Rollback

A compromised or materially broken release must not be silently replaced. Publish a new version and clearly mark/revoke the affected release. Build/release evidence remains immutable.
