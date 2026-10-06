# CI Baseline Validation

This file exists to exercise the Phase 0 pull-request CI from a branch created after the CI workflow became part of the default branch.

Validation target:

- JSON Schema syntax;
- Rust formatting;
- Clippy with warnings denied;
- workspace tests;
- rustdoc warnings denied;
- CLI smoke tests;
- RustSec dependency audit.

The Phase 0 checklist must only mark CI verification complete after the workflow associated with this pull request succeeds.
