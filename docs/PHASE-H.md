# Phase H — Per-Build Diversification

## Objective

Phase H makes protected builds structurally different without changing application semantics.

Diversity is not treated as encryption and is not a replacement for integrity, RASP, VM Shield or backend authorization. Its purpose is to reduce the portability of offsets, signatures, patch recipes and other build-specific bypass knowledge.

The design is deterministic only when the same private build material and the same reproducible context are supplied.

## H.1 — Seed model

`PrivateBuildSeed` stores private build material and redacts it from `Debug`. The memory buffer is zeroized on drop.

`SeedDeriver` derives a private root using HMAC-SHA-256 over:

- application id;
- build id;
- diversity mode;
- mode-specific nonce/reproduction id.

Independent domain keys are then derived for:

- rename;
- pass order;
- CFG;
- integrity topology;
- string partitioning;
- VM map;
- native constants.

A domain output is never reused as another domain's seed.

## H.2 — Reproducible private mode

Two modes are supported:

### unique_build

Requires a build-specific private nonce. Changing the nonce changes the diversification plan even when the application id and build id are unchanged.

### reproducible_private

Requires an explicit reproduction id. Reusing the same private seed and complete build context reproduces the same diversification decisions exactly.

This mode is intended for incident analysis, crash reproduction and controlled rebuilds. Reusing one reproduction context across ordinary releases is not recommended.

## H.3 — Rename diversity

`RenameVariant` derives the seed consumed by the existing DEX `RenamePass`.

The existing compatibility protections remain authoritative:

- reflection-sensitive names;
- Android/runtime contract names;
- shared string entries;
- explicitly protected symbols.

Phase H changes the rename mapping, not the compatibility rules.

The raw rename seed is redacted from `Debug`; only a non-secret fingerprint is exposed for regression comparison.

## H.4 — Pass variants

`PassVariantPlan` changes the order of independent passes while preserving hard dependencies.

Current constrained groups:

1. rename / metadata reduction;
2. string protection / VM Shield / native binding;
3. integrity manifest is always last.

This provides recipe diversity without allowing an arbitrary ordering that could invalidate prior transformations.

## H.5 — CFG variants

`CfgVariantPlan` derives per-method layout decisions:

- seeded block permutation or seeded tail rotation;
- preserve or invert eligible branch style;
- small split budget.

The entry block is always preserved as block zero and the block order is validated as a complete permutation.

This is a layout/transform plan. A DEX rewriter must preserve branch targets and semantics when materializing the plan.

## H.6 — Integrity graph topology variants

`IntegrityTopologyPlan` rebuilds a validated integrity graph using one of three topologies:

- seeded tree;
- layered fanout;
- seeded chain.

The signing certificate remains the single root and the package node remains directly below it. All original integrity nodes and expected digests remain unchanged; only authenticated graph topology changes.

`IntegrityGraph::from_parts` / `with_edges` recompute the graph root and reject invalid or duplicate edges.

## H.7 — String container partition variants

`StringPartitionPlan` assigns logical protected-string ids to a seed-derived number of opaque shards.

Properties:

- configured minimum/maximum partition count;
- duplicate logical ids are deduplicated;
- all emitted shards are non-empty;
- every logical id appears exactly once;
- shard filenames are opaque and build-specific;
- ordering and partition assignment vary by build.

The encrypted string containers themselves remain authenticated by Phase C.

## H.8 — VM map variants

`VmMapVariant` derives a dedicated VM-domain key and feeds it into Phase G's `OpcodeAllocation`.

This gives VM opcode allocation an independent per-build input rather than sharing seed material with rename/CFG/native features.

## H.9 — Native generated constants

`NativeConstantVariant` derives a dedicated native-domain key and feeds it into Phase F's `GeneratedNativeData`.

The resulting generated constants and build tag change independently from other diversification surfaces.

## H.10 — Cross-build bypass regression

`BuildDiversitySignature` records fingerprints for seven independent artifact surfaces:

1. rename mapping seed;
2. pass order;
3. CFG plan;
4. integrity topology;
5. string partitioning;
6. VM opcode map;
7. native generated constants.

`CrossBuildBypassRegression` compares every pair of builds and reports:

- number of builds;
- unique full fingerprints;
- compared build pairs;
- maximum shared surfaces;
- maximum transfer ratio in basis points.

The Phase H CI corpus generates 32 builds from one private test seed with 32 different build contexts. The acceptance gate requires all full fingerprints to be unique and maximum observed surface transfer to remain at or below 3000 basis points.

This is a regression metric for structural portability. It is not a claim that a determined attacker cannot analyze each new build separately.

## Private/public boundary

Private material:

- root diversity seed;
- normal-build nonce;
- reproduction id when operational policy treats it as private;
- private build manifest tying a release to its diversification context.

Safe public/reportable material:

- build diversity fingerprints;
- selected non-secret variant names;
- aggregate portability metrics.

Raw seeds and domain keys must never be included in public build reports.

## Closure requirement

Phase H is complete only when:

1. H.1–H.10 implementation is integrated;
2. private seed redaction and zeroization tests pass;
3. reproducible-private mode reproduces exact plans;
4. unique-build mode changes plans;
5. integrity graphs remain valid after topology diversification;
6. string partitions preserve every item exactly once;
7. VM/native outputs change per build;
8. 32-build bypass portability regression is within budget;
9. Rust quality and Rust 1.81 MSRV pass;
10. Phase A–G regressions remain green.
