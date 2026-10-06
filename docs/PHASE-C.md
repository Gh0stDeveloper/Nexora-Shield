# Phase C — Data Protection

## Status

**Implementation complete; validated by the Phase C CI matrix.**

Phase C introduces the data-protection substrate used to remove high-value plaintext from protected artifacts while preserving explicit compatibility boundaries. The implementation is defensive, selective and fail-closed. It does not treat client-side encryption as a substitute for server-side secret management.

The engine lives in `nexora-shield-crypto` and is exposed through library APIs plus CLI commands for controlled testing and integration.

## Security model

Phase C protects data that must still be available to the application at runtime. Because an attacker controlling the execution environment can eventually observe plaintext after decryption, the objective is to:

- remove trivial static exposure from APK/DEX/resource inspection;
- bind protected data to a build/application context;
- make tampering detectable through authenticated encryption;
- minimize plaintext lifetime in memory;
- avoid reusable plaintext identifiers in public containers;
- measure exposure and size overhead continuously.

High-value credentials that can be moved to a backend should not be shipped in the client at all.

## C.1 — String sensitivity model

Implemented:

- `Public`, `Internal`, `Sensitive` and `Critical` classifications;
- contextual floors for endpoints, authentication, configuration, certificate pins and licensing;
- explicit force-protect and force-public overrides;
- conservative exclusion of JVM/Android runtime contract names;
- heuristics for authentication tokens, API credentials, private-key material, certificate pins, endpoints and other high-value literals;
- redacted debug output and best-effort zeroization of candidate plaintext.

The classifier is policy input, not an oracle. Explicit application knowledge remains authoritative.

## C.2 — Authenticated encrypted containers

Protected values use a versioned `NSC1` binary envelope and XChaCha20-Poly1305.

Authenticated data binds:

- container magic/version;
- semantic container kind;
- opaque per-item identifier;
- build/application context fingerprint;
- plaintext length.

The parser rejects malformed headers, unsupported versions, reserved-bit misuse, inconsistent lengths and authentication failures.

Public containers do not contain the plaintext logical identifier.

## C.3 — Per-build key derivation

`KeySchedule` derives independent material with HKDF-SHA-256 from:

- an external 32-byte root secret;
- application ID;
- build ID;
- protection domain;
- item identity;
- purpose label.

Domains are separated for strings, constants, resources, metadata and generic protected data.

The root secret is held in a zeroizing wrapper and is redacted from `Debug`. CLI integration accepts only an environment-variable reference; raw root keys are never accepted as command-line arguments.

Different build identities produce different opaque IDs, nonces and ciphertext.

## C.4 — Decrypt-on-use runtime

`DecryptRuntime` exposes authenticated decrypt-on-use semantics. Decrypted byte/string wrappers:

- redact their `Debug` representation;
- zeroize owned plaintext on drop where the type permits;
- do not expose cryptographic key material;
- reject invalid UTF-8 when a string is requested.

This Rust runtime is the Phase C substrate. Android/JNI/native injection and platform-specific hardening remain later integration work.

## C.5 — Constant protection

Typed constant encoding supports:

- boolean;
- i32/i64;
- f32/f64;
- byte blobs.

Values are encoded into a stable tagged representation and then placed inside authenticated containers. Unknown tags, malformed lengths and invalid payloads are rejected.

Constant values use redacted diagnostics and best-effort zeroization/reset on drop.

## C.6 — Resource selection

Resource protection is intentionally conservative.

Safe default surfaces:

- `assets/**`;
- `res/raw/**`.

Default exclusions include Android/runtime contract artifacts such as:

- `AndroidManifest.xml`;
- `resources.arsc`;
- `classes*.dex`;
- native libraries;
- `META-INF/**`;
- layouts, XML resources, drawables, mipmaps and values resources.

Selectors support explicit include/exclude patterns and maximum resource-size budgets. Resource paths reject traversal, absolute paths, NULs, backslashes and malformed components.

## C.7 — Resource containers

Selected resources are packed into a versioned `NSRB` bundle.

The public bundle contains:

- opaque item IDs;
- encrypted authenticated per-resource containers;
- structural lengths only.

Plaintext resource paths are not stored in the bundle. The private metadata maps logical paths to opaque identifiers.

Bundle parsing rejects duplicate opaque IDs, truncation, excessive entry counts, malformed sizes and trailing garbage.

## C.8 — Lifetime and caching policies

Plaintext caching is **disabled by default**.

An explicit bounded mode supports:

- maximum entry count;
- maximum plaintext bytes;
- TTL expiration;
- least-recently-used eviction;
- explicit cache clearing;
- cleanup on runtime drop.

Oversized plaintext is not cached. Cache limits are enforced before insertion.

## C.9 — Private metadata

Phase C defines versioned private metadata for authorized build/debug tooling:

- application/build identity;
- non-secret context fingerprint;
- protected string records;
- protected constant records;
- protected resource mappings;
- optional exposure benchmark results.

Private metadata deliberately excludes:

- root secrets;
- derived content keys;
- plaintext protected values.

It must not be published as a public release artifact.

## C.10 — Exposure benchmark

The exposure benchmark compares a baseline artifact with a protected artifact using sensitive probes supplied out-of-band.

It records:

- baseline/protected byte sizes;
- size overhead;
- baseline/protected occurrence counts;
- critical exposures;
- pass/fail against an explicit overhead budget.

Probe contents are redacted from diagnostics and zeroized on drop.

The CLI accepts probes through environment variables so sensitive probe values are not placed in process arguments.

## CLI

~~~text
nexora-shield data-protect <input> ...
nexora-shield data-unprotect <container> ...
nexora-shield data-inspect <container>
nexora-shield data-benchmark <baseline> <protected> ...
nexora-shield data-help
~~~

Root material is supplied with `--key-env <ENV>`, where the environment variable contains exactly 32 bytes represented as 64 hexadecimal characters.

## Cryptographic choices

Phase C currently uses:

- XChaCha20-Poly1305 for authenticated encryption;
- HKDF-SHA-256 for context/domain/item key derivation;
- SHA-256 for content/context hashing;
- constant-time opaque-ID comparison;
- zeroization for owned sensitive buffers where feasible.

Cryptographic dependencies are locked and audited through RustSec. The `zeroize` dependency is pinned to an MSRV-compatible release so the declared Rust 1.81 contract is continuously tested.

## Validation

GitHub Actions run **#216** (ID `37526352684`) validated the final branch head with:

- Rust quality;
- RustSec audit;
- Phase A APK regression;
- Phase B DEX regression;
- Phase C end-to-end data-protection tests;
- Rust 1.81 MSRV tests.

The Phase C job additionally verifies tamper rejection, absence of the critical plaintext probe, exact decrypt round-trip, per-build diversification and an explicit protected-size overhead budget.

## Scope boundary

Phase C does not yet implement:

- APK certificate/content integrity enforcement;
- runtime anti-tamper response;
- debugger/hooking/instrumentation detection;
- native hardening;
- VM virtualization;
- remote attestation.

Those belong to later roadmap phases beginning with Phase D — Integrity / Anti-Tamper.
