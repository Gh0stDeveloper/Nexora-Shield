# Repository conventions

## Canonical layout

    .
    ├── crates/
    │   ├── shield-core/
    │   └── shield-cli/
    ├── docs/
    │   ├── adr/
    │   └── ...
    ├── examples/
    ├── schemas/
    ├── .github/
    │   └── workflows/
    ├── Cargo.toml
    └── rust-toolchain.toml

Only modules that already have code should be created as crates. Future crates listed in the architecture are added in their implementation phase to avoid empty-module drift.

## Ownership boundaries

### shield-core

May contain stable cross-module contracts and orchestration primitives. It must not absorb DEX implementation, RASP collectors or VM interpreter logic merely for convenience.

### shield-cli

Presentation/transport layer over core APIs. It may parse command-line intent but must not own protection algorithms.

## Future top-level areas

- `crates/shield-package`
- `crates/shield-dex`
- `crates/shield-crypto`
- `crates/shield-integrity`
- `crates/shield-rasp`
- `crates/shield-native`
- `crates/shield-vm`
- `crates/shield-diversify`
- `integrations/gradle-plugin`
- `apps/shield-studio`
- `lab/shield-lab`
- `samples/android`

They are introduced only when the corresponding roadmap phase begins.

## Rust policy

- stable Rust;
- edition 2021 during the foundation;
- minimum Rust version 1.81 until deliberately changed;
- `unsafe_code = forbid` workspace policy;
- Clippy warnings are CI failures;
- formatting is enforced;
- application lockfile is committed.

## API policy

Before 1.0, internal APIs may evolve. Public configuration and report formats are explicitly schema-versioned.

Breaking schema changes require:

1. a new schema version;
2. migration notes;
3. updated sample;
4. tests;
5. ADR when architecture changes.

## Dependencies

Dependencies must have a concrete need.

Before introducing a security-sensitive dependency evaluate:

- maintenance;
- license;
- advisories;
- transitive graph;
- unsafe usage;
- cryptographic review status when relevant.

CI includes a RustSec dependency audit baseline.

## Secrets

Repository configuration contains references only. Actual secret material is provided by CI/OS secret providers.

## Generated code

Generated code must contain a header identifying its generator and must be reproducible from tracked inputs where practical.

## Logging

Logs must never expose:

- raw keys;
- seeds;
- full private manifests;
- signing passwords;
- decrypted protected content unless an explicit local debug mode exists.

## Documentation language

Architecture documents may use Spanish with standard English security terminology. Public APIs, identifiers, schemas and source-code comments use English to keep tooling interoperable.

## Definition of done

A roadmap item is DONE only when its code/docs, tests and CI evidence satisfy its exit criterion.
