# Nexora Shield Security Lab methodology

## Scope and authorization

Security Lab runs are limited to Nexora Shield, its bundled fixtures, or targets for which explicit testing authorization exists.

## Reproducibility

Every result must record or pin:

- source revision;
- corpus fingerprint;
- toolchain version;
- target type;
- protection profile;
- relevant budget;
- raw measurement or verifier output needed to reproduce the conclusion.

## Tamper testing

Repack and re-sign tests are expected-failure tests. A clean fixture must first pass verification. The test then changes exactly one security-relevant dimension and requires the same verifier to reject it.

## Fuzzing

Malformed input rejection is not counted as a failure. A panic, process abort caused by parser state, or uncontrolled resource blow-up is a failure and must produce a minimized corpus case before release.

## Performance comparison

Do not compare measurements captured on materially different hardware, OS images or toolchains. Use warm-ups, repeated measured runs and raw-sample retention. Report medians/p95 where appropriate and keep size overhead independent from runtime overhead.

## Security score

The score summarizes evidence; it is not a claim that software is unbreakable. Critical control failures cap the score and block release regardless of aggregate percentage.

## Bypass lifecycle

1. reproduce on an authorized target;
2. assign a stable corpus id;
3. add a failing regression;
4. implement remediation;
5. verify the regression passes;
6. retain the case permanently unless the protected surface is removed;
7. include the case in release qualification.
