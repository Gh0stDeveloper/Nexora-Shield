# Phase M — Security Lab

## Objective

Phase M turns Nexora Shield security assumptions into repeatable, release-blocking regression evidence.

The Security Lab is defensive and authorization-scoped. It is intended for Nexora Shield itself, bundled samples, and applications for which the operator has permission to test. It does not provide stealth, persistence, credential theft, or exploitation tooling.

The implementation lives in `crates/shield-lab` and the versioned regression corpus under `security-lab/corpus/`.

## M.1 — Static exposure harness

The lab scans owned/test artifacts for explicitly supplied synthetic markers and enforces a maximum occurrence budget.

Rules are named and results are serializable. The CLI accepts marker material through an environment variable so the value is not echoed into the command line.

## M.2 — Repack harness

Release CI creates clean integrity evidence, mutates protected DEX/resource/native inputs and requires verification to fail closed.

The lab records each tamper case as a typed result so failures enter the same regression/reporting path as the remaining Phase M controls.

## M.3 — Re-sign harness

CI creates two independent signing identities. Integrity evidence bound to signer A must reject signer B. The test is certificate-bound and independent from package-content mutation.

## M.4 — Runtime instrumentation lab

The lab feeds real Phase E `InstrumentationEvaluator` and `HookInjectionEvaluator` evidence into the production `RiskEngine` and `ResponseEngine`.

Critical definitive instrumentation evidence must escalate according to the configured policy.

## M.5 — Modified-environment matrix

Modified-system and emulator observations are evaluated through the real RASP pipeline. Matrix cases define minimum acceptable risk/response behavior and exercise cross-category correlation.

## M.6 — Automated bypass portability

The lab wraps Phase H `CrossBuildBypassRegression`. Builds must retain unique full fingerprints and remain below a declared maximum transfer budget.

## M.7 — Fuzz farm

A deterministic mutation farm exercises parser-like targets with bit flips, truncation, appended data and reordered prefixes.

Rejected malformed inputs are valid outcomes. Panics are not.

## M.8 — Performance farm

The lab evaluates measured baseline/protected samples against explicit runtime and size overhead budgets and records p95 protected latency.

No timing threshold is inferred from CI hardware; CI validates the evaluation logic while release benchmarking supplies controlled samples.

## M.9 — Regression corpus

Known bypass classes and security regressions live in `security-lab/corpus/index.json`.

Requirements:

- schema versioned;
- stable lowercase ids;
- unique ids;
- explicit expected outcome;
- reproducible corpus fingerprint;
- new confirmed bypasses must be added before the fix is considered release-complete.

## M.10 — Security score

Security controls receive explicit weights. The aggregate score is reported in basis points.

A failed critical control caps the score below the passing grade range so strong non-critical results cannot hide a critical regression.

## M.11 — Comparative benchmark methodology

Baseline and protected runs must use:

- the same physical/virtual device profile;
- the same OS image;
- the same toolchain;
- at least two warm-up runs;
- at least ten measured runs;
- retained raw samples.

The default methodology is stricter: five warm-ups and thirty measured runs.

## M.12 — External audit preparation

Audit readiness requires:

- threat model;
- security policy;
- phase checklists;
- regression corpus;
- benchmark methodology;
- CI evidence;
- classified evidence inventory.

Confidential evidence cannot be exported as audit-ready unless it is explicitly redacted. Absolute or traversal paths are rejected.

## Release rule

Every confirmed security bypass must become a regression-corpus case and a repeatable gate before the associated remediation is considered complete.

Phase M is complete only when M.1–M.12 are implemented, the real repackage/re-sign integration tests pass, Rust 1.81 remains supported, Phase L/K regressions remain green, and the repository CI has no failures.


## Closure status

**COMPLETED**

Validated implementation head: `f09e950c8269688e085e104f62531427fe58b736`.

Final validation:
- Phase M #47 (`37639187441`): **success** — 6/6 jobs.
- Rust 1.81 MSRV: **success**.
- Real M.2/M.3 repack and re-sign rejection: **success**.
- Phase H/M.6 cross-build portability regression: **success**.
- Phase L Studio regression: **success**.
- Phase K package-model regression: **success**.
- CI #1006 (`37639187513`): **success** — 24/24 jobs.
- Failed jobs: **0**.

Phase M exit criterion is satisfied: known bypass classes are represented in the versioned corpus and the validated gates execute on release CI.
