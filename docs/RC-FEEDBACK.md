# Nexora Shield 1.0 RC feedback

N.13 requires real external feedback before stable 1.0.

## What to test

Useful RC feedback includes:

- installation/build setup;
- CLI behavior;
- Gradle Plugin integration;
- Shield Studio workflows;
- APK/AAB/AAR/APKS verification;
- compatibility with supported Android/Gradle environments;
- false positives in runtime protections;
- performance regressions;
- documentation gaps.

## What not to submit publicly

Do not include:

- keystores or signing private keys;
- passwords or tokens;
- build seeds/nonces;
- private mappings/manifests;
- customer or personal data.

Sensitive security findings should follow [SECURITY.md](../SECURITY.md).

## Stable evidence rule

Only feedback from a real external tester/reviewer counts toward `release/feedback-status.json`. Internal CI, automated bots and the project owner do not count as external reviewers.

A stable release remains blocked while:

- external reviewer count is below policy;
- a blocking RC finding remains open;
- stable device performance evidence is incomplete.
