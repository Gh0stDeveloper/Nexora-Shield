# Contributing to Nexora Shield

## Development contract

Nexora Shield is security-sensitive tooling. A change is not complete because it compiles. Changes must preserve correctness, compatibility, security assumptions and observability.

## Branches

Use short-lived branches:

- `feat/<scope>`
- `fix/<scope>`
- `docs/<scope>`
- `security/<scope>`
- `refactor/<scope>`

Direct development on `main` is discouraged once branch protection is enabled.

## Commits

Use Conventional Commits:

- `feat:`
- `fix:`
- `docs:`
- `test:`
- `refactor:`
- `build:`
- `ci:`
- `security:`

One commit should represent one coherent change.

## Required local checks

~~~bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo doc --workspace --no-deps
~~~

## Security-sensitive changes

Changes involving any of the following require an ADR or an update to an existing ADR when the architectural decision changes:

- cryptographic design;
- DEX IR invariants;
- signing;
- private build artifacts;
- RASP evidence;
- VM semantics;
- remote attestation;
- secrets handling.

Never implement custom cryptographic primitives to replace established algorithms.

## Pull requests

A PR should state:

1. problem;
2. design;
3. security impact;
4. compatibility impact;
5. performance impact;
6. tests performed;
7. rollback/migration notes if applicable.

## Tests

All behavior changes require tests. A bypass or parser crash becomes a regression test whenever it can be safely represented in the repository.

## Private material

Never commit:

- signing keys;
- passwords;
- private seeds;
- production tokens;
- private build manifests;
- symbol/VM mappings from protected production applications.

## Unsafe Rust

The workspace forbids `unsafe_code` by default. A future crate that genuinely requires unsafe code must isolate it, document invariants and introduce an ADR before changing this policy.

## Generated artifacts

Do not commit build output. Stable test fixtures may be committed only when they are intentionally reviewed, legally redistributable and documented.

## Responsible research

Use Nexora Shield security tests only against applications you own, project samples, or software for which you have explicit authorization.
