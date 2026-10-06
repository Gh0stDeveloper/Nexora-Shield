# Phase D — Integrity / Anti-Tamper

## Objective

Phase D binds a protected build to its signing identity and package identity, fingerprints security-relevant content, distributes verification responsibility across multiple check points, and returns an auditable non-destructive response when tampering is detected.

The design does **not** assume that a single client-side check is unpatchable. The integrity layer is intentionally decomposed into independently addressable graph nodes so later RASP/native layers can execute the same evidence at different runtime locations.

## D.1 — Certificate binding

Implemented by `CertificateBinding` and `CertificateObservation`.

Properties:

- SHA-256 signer certificate digests;
- exact-current signer policy;
- current-or-lineage policy for legitimate signing-key rotation;
- multiple allowed signer digests;
- deterministic binding fingerprint;
- explicit rejection of re-signed builds.

The core consumes normalized signer evidence. Android-specific collection through `SigningInfo` is a runtime adapter concern; this phase defines and verifies the cryptographic identity contract without depending on Android framework APIs inside the portable core.

## D.2 — Package identity

`PackageBinding` binds:

- application ID;
- version code;
- optional split name.

The comparison is exact and fail-closed. Package-name/version/split drift is treated as integrity evidence rather than silently accepted.

## D.3 — DEX regions

`DexIntegrity` parses and validates DEX through the Phase B engine, then fingerprints:

- DEX file;
- header;
- string IDs;
- type IDs;
- proto IDs;
- field IDs;
- method IDs;
- class definitions;
- data section chunks.

The data section is chunked so a modification can invalidate a local region as well as the whole-file digest. Region offsets and lengths are bounds-checked.

## D.4 — Resource integrity

`ArtifactIntegrity` protects selected resources by logical path, size and SHA-256 digest.

Paths are normalized and path traversal/backslash/absolute-path forms are rejected.

## D.5 — Native integrity

The same artifact primitive treats native libraries as critical nodes. Native-library replacement, extension or truncation changes the expected size/digest and produces critical evidence.

## D.6 — Integrity Graph

`IntegrityGraph` constructs a certificate-rooted graph:

~~~text
certificate
    |
 package
   / | \
 DEX resources native
  |
DEX regions
~~~

Each node has:

- deterministic node ID;
- kind;
- logical label;
- expected digest/fingerprint;
- criticality.

The graph root is deterministically recomputed from sorted nodes and edges. A serialized manifest whose graph no longer matches its certificate/package/content records is rejected before verification.

## D.7 — Distributed checks

`DistributionPlan` assigns every graph node to multiple check points using a deterministic seed and configurable redundancy.

Rules:

- at least two check points;
- positive redundancy;
- a node cannot be duplicated inside one check point;
- every node must appear exactly the configured number of times;
- assignments change when the distribution seed changes;
- a check can verify only its assigned subset through `IntegrityVerifier::verify_check`.

This avoids designing the integrity system around a single central boolean.

## D.8 — Response API

The integrity engine returns a structured verdict:

- clean/failed;
- maximum severity;
- checks passed/total;
- detailed failures;
- expected/observed digest when available;
- recommended response.

Default responses are intentionally non-destructive:

- info -> continue;
- warning -> report;
- high -> require reverification;
- critical -> deny sensitive operation.

Process termination, destructive behavior and stealth responses are not part of this layer.

## D.9 — Re-sign tests

The test matrix contains both synthetic unit evidence and a GitHub Actions end-to-end signing test.

CI:

1. generates two independent PKCS12 signers;
2. signs equivalent APK fixtures independently;
3. extracts the signer SHA-256 digests with official `apksigner`;
4. builds the manifest against signer A;
5. verifies signer A succeeds;
6. verifies signer B is rejected as a re-sign.

## D.10 — Patch / repack tests

The permanent Phase D gate checks:

- clean evidence passes;
- modified resource is rejected;
- modified DEX is rejected;
- replaced native library is rejected;
- re-signed APK identity is rejected;
- repackaged package identity is rejected;
- distributed check execution works independently;
- missing DEX/artifact evidence fails closed.

## CLI

Phase D adds:

~~~text
nexora-shield integrity-create ...
nexora-shield integrity-inspect <manifest.json>
nexora-shield integrity-verify <manifest.json> ...
nexora-shield integrity-help
~~~

The CLI accepts signer digests as explicit evidence and content mappings in `logical-name=file` form. Production Android adapters should collect signer/package evidence from platform APIs rather than accepting it from an untrusted caller.

## Security boundary

The signing certificate is the graph trust root because modifying and re-signing an APK changes the signer identity. On a device fully controlled by an attacker, runtime checks can still be hooked or bypassed. Phase D therefore raises tamper cost and establishes distributed evidence; Phase E (RASP), Phase F (Native Shield) and later diversification layers harden how and where those checks execute.

No client-side integrity implementation is claimed to be impossible to bypass.

## Acceptance

Phase D is complete only when:

- B/D unit tests pass;
- Rust quality/Clippy/rustdoc pass;
- RustSec passes;
- Phase A/B/C regressions stay green;
- Rust 1.81 MSRV passes;
- real signer A vs signer B test passes;
- DEX/resource/native/package patch tests fail closed;
- documentation and configuration schema match the implementation.


## Closure evidence

Pull-request validation run **#264** (ID `37542495923`) passed the complete Phase D acceptance matrix:

- Rust quality and documentation;
- RustSec audit;
- Phase A/B/C regression gates;
- Rust 1.81 MSRV for integrity and CLI;
- two independent PKCS12 signing identities;
- official `apksigner` signer evidence;
- clean distributed verification;
- re-sign rejection;
- DEX patch rejection;
- resource patch rejection;
- native replacement rejection;
- package-identity repack rejection.

No known critical Phase D error remains at closure.
