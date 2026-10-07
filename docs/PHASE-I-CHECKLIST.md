# Phase I — Attestation & Remote Policy checklist

## I.1 Attestation abstraction
- [x] Client provider trait
- [x] Server verifier trait
- [x] Typed opaque evidence
- [x] App/build/purpose/session/nonce binding
- [x] Token Debug redaction
- [x] Token zeroization

## I.2 Nonce/session model
- [x] 128-bit session id
- [x] 256-bit nonce
- [x] Separate HMAC domains
- [x] 32-byte server key
- [x] Explicit server-instance id
- [x] Monotonic issuance counter
- [x] Default TTL
- [x] Hard maximum TTL

## I.3 Anti-replay
- [x] Registered-session store
- [x] Bounded capacity
- [x] Constant-time nonce comparison
- [x] One-time consume
- [x] Expiry pruning
- [x] Consume before evidence verification
- [x] Replay regression test

## I.4 Server verification sample
- [x] Generic server verifier
- [x] Compile-tested server example
- [x] Deterministic sample evidence authenticator
- [x] Provider-specific verifier boundary
- [x] Shared-store production guidance

## I.5 Signed policy
- [x] Signed envelope
- [x] Key id binding
- [x] Algorithm binding
- [x] Ed25519 identifier
- [x] ES256 identifier
- [x] Pluggable signer/verifier interfaces
- [x] Tamper detection
- [x] Sequence rollback protection
- [x] Application binding
- [x] Sample-only HMAC implementation with explicit warning

## I.6 Build revocation
- [x] Exact build-id revocation
- [x] Reason code
- [x] Revocation timestamp
- [x] Revocation checked before feature/offline rules
- [x] Fail-closed regression test

## I.7 Feature-specific thresholds
- [x] Per-feature maximum local risk
- [x] Per-feature attestation requirement
- [x] Per-feature offline override
- [x] Unknown feature fails closed
- [x] Threshold independence regression test

## I.8 Offline degradation
- [x] Allow action
- [x] Degrade action
- [x] Deny action
- [x] Bounded stale-policy grace
- [x] Online refresh requirement for expired policy
- [x] Too-stale fail-closed behavior

## I.9 Privacy docs
- [x] Data-minimization contract
- [x] Prohibited identifier list
- [x] Token lifetime guidance
- [x] Logging guidance
- [x] Network metadata note
- [x] Typed privacy audit regression

## I.10 Integration tests
- [x] I.1-I.10 protocol tests
- [x] End-to-end attestation flow
- [x] End-to-end policy evaluation
- [ ] Final dedicated CI gate

## Closure state

Phase I implementation is **IN PROGRESS**. Code, protocol tests, configuration and documentation are present. The phase is not closed until strict Rust quality, Rust 1.81 MSRV, dedicated Phase I integration CI and all Phase A-H regressions are green on the final head.
