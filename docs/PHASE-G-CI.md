# Phase G CI validation

Phase G is closed only after the complete G.1–G.14 implementation and regression matrix passes on the final implementation head.

## Acceptance run

GitHub Actions run **#584** (ID `37571516228`) completed successfully on commit `986f8a869fef5fd59819270b512cff1de28e3d25`.

Validated jobs:

- Rust quality — success;
- RustSec audit — success;
- Phase A APK pipeline — success;
- Phase B DEX engine — success;
- Phase C Data Protection — success;
- Phase C Rust 1.81 MSRV — success;
- Phase D Integrity / Anti-Tamper — success;
- Phase D Rust 1.81 MSRV — success;
- Phase E RASP E.1–E.12 — success;
- Phase E RASP Rust 1.81 MSRV — success;
- Phase F Native Shield host — success;
- Phase F Native Shield Rust 1.81 MSRV — success;
- Phase F Android arm64 + x86_64 — success;
- Phase G VM Shield G.1–G.14 — success;
- Phase G VM Shield Rust 1.81 MSRV — success;
- Phase G differential + security — success.

## Phase G acceptance properties

The final VM gate validates:

- fail-safe eligibility and unsupported-opcode rejection;
- typed VM IR and method validation;
- operand-bearing encoded VM bytecode;
- per-build opcode allocation;
- DEX lowering for the declared supported subset;
- encoded and sealed execution;
- typed/catch-all exception semantics with host assignability;
- explicit calls/fields host boundary;
- constant-pool integrity;
- HMAC-SHA-256 executable metadata sealing;
- bytecode and opcode-allocation tamper rejection;
- static performance estimation;
- deterministic differential semantics;
- configuration/annotation selection;
- 32-build opcode-diversity security benchmark;
- Rust 1.81 compatibility.

No known critical Phase G error remains at closure.

The documentation-only closure commit is revalidated by CI before merge to `main`.
