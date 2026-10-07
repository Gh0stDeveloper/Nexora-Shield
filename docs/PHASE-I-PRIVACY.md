# Phase I — Privacy contract

## Data minimization

The Phase I request type contains only the fields required to bind a server challenge and evaluate a protected feature:

- application id;
- protected build id;
- feature identifier;
- normalized local RASP risk level;
- attestation provider id;
- server challenge/session values;
- opaque provider attestation token.

Nexora Shield Phase I does **not** define fields for:

- IMEI;
- IMSI;
- phone number;
- Android ID;
- advertising ID;
- device serial number;
- MAC address;
- contacts;
- account email;
- precise/coarse location;
- installed-application inventory;
- arbitrary device property dictionaries.

Provider-specific attestation tokens are opaque to the Android-facing core API. A production verifier may receive provider claims according to that provider's contract, but applications should request only the minimum attestation tier needed for the protected operation.

## Token lifetime

Raw attestation tokens are:

- redacted from Rust `Debug`;
- zeroized when `AttestationEvidence` is dropped;
- intended for immediate server verification;
- not part of public build reports;
- not intended for analytics/event payloads.

Production server implementations should avoid persisting raw tokens. If incident retention is required, define an explicit retention period and access control outside the client protocol.

## Logging

Recommended logs contain normalized results rather than raw evidence:

- provider id;
- build id;
- feature id;
- normalized risk level;
- attestation verdict;
- machine-readable reason code;
- policy sequence;
- request/session correlation id where operationally required.

Do not log:

- opaque token bytes;
- signing/MAC keys;
- complete policy private signing material;
- provider credentials;
- stable device identifiers.

## Network metadata

Normal network infrastructure may observe IP addresses at the transport layer. The Phase I application payload does not add an IP-address field and the core library does not require IP storage.

Operators are responsible for documenting server/proxy logs and retention separately.

## Privacy audit helper

`PrivacyAudit::inspect_request` reports the categories represented by the typed request and explicitly records that the protocol contains zero free-form device metadata fields and zero stable-device-identifier fields.

This helper is a regression guard for the protocol shape, not a legal-compliance certification.

## Sample HMAC warning

The repository contains HMAC-based evidence/policy helpers strictly to keep deterministic tests and examples dependency-light.

Do not embed those shared verification keys in a production Android app. Production remote policy should use an asymmetric signature verifier such as Ed25519 or ES256, ideally backed by controlled key management.
