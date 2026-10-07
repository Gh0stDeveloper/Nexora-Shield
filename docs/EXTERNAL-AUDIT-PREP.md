# External security audit preparation

## Audit packet

Prepare a redacted packet containing:

- threat model and security design;
- architecture and trust boundaries;
- supported configuration/profile documentation;
- Phase M regression corpus fingerprint;
- current CI evidence;
- public build/security reports;
- comparative benchmark methodology and raw non-sensitive samples;
- known limitations and non-goals;
- release/version identifier.

## Never export

- signing private keys or keystores;
- passwords;
- production tokens;
- private build seeds/nonces;
- private `.nshield` manifests;
- customer data;
- unredacted confidential paths or environment dumps.

## Evidence classification

Each audit item is classified as:

- `public`;
- `confidential`;
- `secret_reference_only`.

Confidential and secret-reference-only evidence must be redacted before inclusion in an exportable packet.

## Auditor expectations

The auditor should be able to reproduce:

- static-exposure gates;
- repack rejection;
- re-sign rejection;
- runtime risk-policy behavior;
- modified-environment behavior;
- cross-build diversity portability;
- corpus validation;
- fuzz panic gates;
- performance calculations;
- score calculations.

Nexora Shield does not claim invulnerability. Findings are expected to become permanent regression cases.
