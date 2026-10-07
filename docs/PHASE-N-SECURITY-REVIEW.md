# Nexora Shield 1.0 RC — internal security review

## Scope

This is the internal production-hardening review for the 1.0 release candidate. It is not a substitute for N.13 external feedback.

Reviewed evidence:

- Phase M Security Lab;
- Phase D anti-tamper/re-sign regressions;
- Phase E RASP/risk policy regressions;
- Phase H cross-build portability;
- RustSec dependency audit;
- secret-reference boundaries in Gradle Plugin and Shield Studio;
- release workflow permissions and provenance.

## Release blockers

RC qualification fails when any of these are non-zero:

- critical findings;
- high findings;
- blocking findings.

Machine-readable state is stored in `../release/security-review.json`.

## Security posture

Nexora Shield makes no claim of being impossible to reverse engineer. The release goal is measurable defense in depth, fail-closed verification for defined tamper cases, reduced cross-build bypass portability and auditable release evidence.

Any newly confirmed bypass must enter the Phase M regression corpus before its remediation is considered release-complete.
