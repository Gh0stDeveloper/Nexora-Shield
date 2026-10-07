# Phase M — Security Lab checklist

## M.1 Static exposure harness
- [x] Named exposure rules
- [x] Synthetic marker scanning
- [x] Maximum-occurrence budgets
- [x] Non-echoing environment-variable CLI input
- [ ] Final static exposure CI gate

## M.2 Repack harness
- [x] Typed repack cases
- [x] DEX mutation case
- [x] Resource mutation case
- [x] Native replacement case model
- [ ] Final real integrity-rejection CI gate

## M.3 Re-sign harness
- [x] Typed re-sign case
- [ ] Independent signer A/B CI fixture
- [ ] Final certificate-binding rejection gate

## M.4 Runtime instrumentation lab
- [x] Production instrumentation evaluator integration
- [x] Production hook evaluator integration
- [x] Production RiskEngine integration
- [x] Production ResponseEngine integration
- [x] Minimum risk/response assertions
- [ ] Final runtime-lab CI gate

## M.5 Modified-environment matrix
- [x] Modified-system observations
- [x] Emulator observations
- [x] Cross-category signal fusion
- [x] Minimum risk/response assertions
- [ ] Final environment-matrix CI gate

## M.6 Automated bypass portability
- [x] Phase H regression integration
- [x] Full-fingerprint uniqueness gate
- [x] Transfer budget gate
- [ ] Final portability CI gate

## M.7 Fuzz farm
- [x] Deterministic mutations
- [x] Bit-flip cases
- [x] Truncation cases
- [x] Append cases
- [x] Reorder cases
- [x] Panic accounting
- [ ] Final fuzz CI gate

## M.8 Performance farm
- [x] Runtime overhead evaluation
- [x] Artifact-size overhead evaluation
- [x] p95 protected latency
- [x] Explicit budgets
- [ ] Final performance CI gate

## M.9 Regression corpus
- [x] Versioned schema
- [x] Stable unique case ids
- [x] Expected outcomes
- [x] Reproducible fingerprint
- [x] Initial M.1-M.12 corpus
- [ ] Final corpus validation gate

## M.10 Security score
- [x] Weighted controls
- [x] Basis-point score
- [x] Letter grade
- [x] Critical-control score cap
- [ ] Final scoring CI gate

## M.11 Comparative benchmark methodology
- [x] Warm-up minimum
- [x] Measurement minimum
- [x] Same-device requirement
- [x] Same-OS requirement
- [x] Same-toolchain requirement
- [x] Raw-sample retention requirement
- [ ] Final methodology CI gate

## M.12 External audit preparation
- [x] Required evidence inventory
- [x] Evidence classification
- [x] Confidential redaction gate
- [x] Path traversal rejection
- [ ] Final audit-readiness CI gate

## Closure state

Phase M is **IN PROGRESS** until all final CI gates and repository regressions are green.
