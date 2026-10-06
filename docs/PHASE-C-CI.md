# Phase C CI validation

Phase C is accepted only after the complete data-protection implementation passes the repository's strict validation matrix.

Required gates:

- Rust formatting;
- Clippy with warnings denied;
- complete workspace tests;
- rustdoc with warnings denied;
- RustSec audit;
- Phase A APK regression;
- Phase B DEX regression;
- Phase C authenticated data-protection end-to-end tests;
- tamper rejection;
- plaintext exposure check;
- per-build diversification check;
- declared Rust 1.81 MSRV for both the crypto crate and CLI.

The dependency lockfile is part of the compatibility contract. Cryptographic dependencies must remain compatible with the declared MSRV and are not allowed to float to an edition/toolchain that the workspace cannot build.
