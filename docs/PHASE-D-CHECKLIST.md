# Phase D — Integrity / Anti-Tamper checklist

## D.1 Certificate binding
- [x] SHA-256 certificate identity
- [x] Exact-current policy
- [x] Signing-lineage policy
- [x] Multiple allowed signers
- [x] Re-sign mismatch evidence

## D.2 Package identity
- [x] Application ID
- [x] Version code
- [x] Split identity
- [x] Exact fail-closed comparison

## D.3 DEX regions
- [x] Full-file digest
- [x] Header region
- [x] DEX ID-table regions
- [x] Class-def region
- [x] Chunked data regions
- [x] Bounds validation
- [x] Patch detection

## D.4 Resource integrity
- [x] Logical path binding
- [x] Size binding
- [x] SHA-256 binding
- [x] Unsafe path rejection

## D.5 Native integrity
- [x] Native path binding
- [x] Size/digest verification
- [x] Critical severity
- [x] Replacement detection

## D.6 Integrity Graph
- [x] Certificate root
- [x] Package/content descendants
- [x] Deterministic node IDs
- [x] Deterministic graph root
- [x] Graph/manifest consistency validation

## D.7 Distributed checks
- [x] Seeded deterministic assignment
- [x] Configurable check count
- [x] Configurable redundancy
- [x] Exact coverage validation
- [x] Independent check verification API

## D.8 Response API
- [x] Structured verdict
- [x] Severity
- [x] Failure details
- [x] Report
- [x] Require reverification
- [x] Deny sensitive operation
- [x] No destructive response behavior

## D.9 Re-sign tests
- [x] Unit-level signer mismatch
- [x] Real independent PKCS12 keys in CI
- [x] Official apksigner signer digest extraction
- [x] Final CI closure run

## D.10 Patch/repack tests
- [x] DEX patch unit test
- [x] Resource patch unit test
- [x] Native replacement unit test
- [x] Package identity repack unit test
- [x] Missing evidence fail-closed test
- [x] Final CI closure run

## Closure state

All D.1–D.10 implementation and adversarial gates are complete. Pull-request validation run #264 (`37542495923`) passed every required job, including the real two-signer re-sign scenario and patch/repack rejection matrix.

The merge to `main` is performed only from this validated head; post-merge CI is the final repository-state confirmation.
