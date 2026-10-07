# Phase I — Attestation & Remote Policy

## Objective

Phase I lets sensitive application decisions incorporate server-verified evidence without turning Nexora Shield into an always-online protection system.

It is **optional**. Applications designed to run entirely offline do not need Phase I.

The Phase I trust model is deliberately asymmetric:

- local integrity/RASP controls continue to run without the server;
- remote attestation can add confidence or impose stricter feature decisions;
- remote policy never makes local evidence disappear;
- offline behavior is explicitly configured per feature;
- stale remote policy has a bounded grace window;
- revoked builds fail closed.

No attestation API is described as an absolute trust anchor on an attacker-controlled Android device.

## I.1 — Attestation abstraction

The crate `nexora-shield-attestation` defines two independent interfaces:

- `AttestationProvider`: client-side evidence collection;
- `AttestationEvidenceVerifier`: server-side verification.

The core does not hard-code Google Play Integrity or another provider. A provider adapter can return opaque evidence while the verifier performs provider-specific server checks.

`AttestationEvidence` binds:

- provider id;
- application id;
- build id;
- purpose;
- session id;
- nonce;
- opaque token.

The token is redacted from `Debug` and zeroized on drop.

## I.2 — Nonce/session model

`ChallengeDeriver` creates a challenge from:

- a 32-byte private server key;
- an explicit 16-byte `server_instance_id`;
- application id;
- build id;
- purpose;
- current timestamp;
- monotonic issuance counter.

Session id and nonce use separate HMAC-SHA-256 domains.

The default challenge TTL is 120 seconds. The hard maximum is 10 minutes.

Production servers must provision a unique server-instance identifier when a process/lease is created and must never share a challenge key with the Android client.

## I.3 — Anti-replay

`ReplayGuard` records issued sessions and enforces one-time consumption.

A request is accepted only when all challenge fields match the registered session. Nonces are compared in constant time.

The challenge is consumed **before** provider evidence verification. A malformed or rejected evidence attempt therefore cannot be retried with the same server challenge.

The in-memory `ReplayGuard` is the reference implementation. Multi-node production deployments should back the same semantics with an atomic shared store such as Redis/PostgreSQL using TTL + compare-and-consume.

## I.4 — Server verification sample

`SampleRemotePolicyServer<V>` demonstrates the server sequence:

1. register server-issued challenge;
2. receive minimal attestation request;
3. validate evidence/challenge binding;
4. atomically consume challenge;
5. invoke provider-specific evidence verifier;
6. return normalized `AttestationVerification`.

A compile-tested example is provided at:

`crates/shield-attestation/examples/server_verification.rs`

`SampleHmacEvidenceAuthenticator` exists only for deterministic repository tests/examples. It is **not** a substitute for Google Play Integrity, hardware-backed attestation, or another production provider.

## I.5 — Signed policy

Remote policy is transported as `SignedPolicyEnvelope`.

The signature/authentication input binds:

- protocol domain;
- key id;
- algorithm id;
- canonical serialized policy payload.

Supported algorithm identifiers are:

- Ed25519;
- ES256;
- HMAC-SHA-256 sample.

The core exposes `PolicySigner` and `PolicySignatureVerifier`, so production applications can connect Ed25519/ES256 implementations or KMS/HSM-backed verification without giving the core crate custody of private signing keys.

`SampleHmacPolicyAuthenticator` is test/sample infrastructure only. A shared HMAC key must **not** be embedded in a hostile Android client because extraction would permit policy forgery.

Policy verification rejects:

- unknown/untrusted key id;
- algorithm mismatch;
- invalid signature;
- application mismatch;
- sequence rollback;
- not-yet-valid policy.

Expired policies can still be cryptographically verified so I.8 can make an explicit bounded offline decision.

## I.6 — Build revocation

A signed policy can contain exact build-id revocations.

Revocation is checked before feature thresholds or offline fallback. A known revoked build is denied even when the device is offline and using a cached signed policy.

Revocation entries contain a machine-readable reason code and revocation timestamp.

## I.7 — Feature-specific thresholds

Each feature receives its own `FeaturePolicy`:

- maximum accepted local RASP risk;
- whether verified attestation is required;
- optional offline action.

Unknown features fail closed.

A low-risk media/read-only feature can remain usable under conditions where a billing, licensing, account-recovery or entitlement feature is denied.

## I.8 — Offline degradation

Offline behavior is explicit:

- `allow`;
- `degrade`;
- `deny`.

The policy also defines `max_staleness_ms`. After that bounded interval, an expired cached policy fails closed.

When the network is available but a policy is expired, the engine returns `require_online_verification` rather than silently applying stale rules.

This is how Phase I satisfies the roadmap requirement that remote evidence can protect sensitive operations without unnecessarily making an offline-capable application unusable.

## I.9 — Privacy

See [PHASE-I-PRIVACY.md](PHASE-I-PRIVACY.md).

The typed request intentionally has no generic device-metadata map and no fields for stable hardware/device identifiers.

## I.10 — Integration tests

`crates/shield-attestation/tests/phase_i.rs` covers:

- provider abstraction and token redaction;
- unique nonce/session derivation and TTL;
- replay rejection;
- server verification and consume-on-failure;
- signed-policy tamper detection;
- sequence rollback;
- build revocation;
- independent per-feature thresholds;
- bounded offline degradation;
- privacy request shape;
- complete challenge → evidence → server verification → signed policy → feature decision flow.

## Security boundary

Phase I raises the cost of replay, policy forgery and reuse of compromised builds. It does not make code executing on an attacker-controlled device impossible to patch.

Server-side authorization for high-value assets or account operations remains authoritative where applicable.


## Closure state

Phase I is **COMPLETED**. GitHub Actions run **#709** (ID `37576325958`) passed the complete implementation acceptance matrix on commit `86152ab0abd2a212354483a82be56488cd2fa15c`.

The closure includes Rust quality, RustSec, Rust 1.81 MSRV, all Phase A–H regressions, I.1–I.10 tests, the end-to-end attestation/policy integration gate and compilation of the server-verification example.
