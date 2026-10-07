# Nexora Shield 1.0 external assessment and feedback

N.13 has two distinct channels: a machine-enforced independent assessment gate and optional human RC feedback.

## Independent assessment gate

The stable release policy requires at least one external assessment provider.

For 1.0, the recorded provider is **GitHub CodeQL**:

- Phase N #54;
- run `37686651703`;
- job `N.13 independent external assessment`;
- conclusion: `success`.

This evidence is recorded in `../release/feedback-status.json`.

Internal unit tests and self-review do not count as the independent assessment.

## Human feedback

Human testers and reviewers can still report:

- installation/build setup issues;
- CLI behavior;
- Gradle Plugin integration;
- Shield Studio workflows;
- APK/AAB/AAR/APKS compatibility;
- false positives in runtime protections;
- performance regressions;
- documentation gaps.

Human feedback is supplementary to the machine gate. Any blocking external finding that is recorded must be resolved before stable publication.

## What not to submit publicly

Do not include:

- keystores or signing private keys;
- passwords or tokens;
- build seeds/nonces;
- private mappings/manifests;
- customer or personal data.

Sensitive security findings must follow [SECURITY.md](../SECURITY.md).

## Stable evidence rule

Stable remains fail-closed while any of these are true:

- the configured independent external-assessment count is not satisfied;
- a blocking external finding remains open;
- N.10 representative Android performance evidence is incomplete;
- the final stable qualification workflow is not green.
