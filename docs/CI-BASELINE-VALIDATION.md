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

## Resultado

Validación completada el 2026-10-06.

- Workflow: `CI`
- Run: `#28`
- Run ID: `37504965228`
- `Rust quality`: **success**
- `RustSec audit`: **success**

Durante la validación se detectaron y corrigieron dos problemas reales del baseline:

1. Clippy 1.99 exige prioridades explícitas cuando grupos como `all` y `pedantic` coexisten con lints individuales.
2. `cargo-audit 0.22.2` no acepta `--locked`; el workflow usa ahora la invocación compatible `cargo audit`.

Esto confirma que la Fase 0 no se cerró únicamente por revisión documental: el pipeline fue ejecutado y las regresiones encontradas se corrigieron antes del cierre.
