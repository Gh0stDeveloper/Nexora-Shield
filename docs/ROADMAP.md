# Roadmap de desarrollo

Este roadmap divide Nexora Shield en fases con criterios de salida verificables. No se avanza una fase crítica solo porque "compile".

## Fase 0 — Foundation

### 0.1 Vision
- alcance;
- no-objetivos;
- principios.

### 0.2 Threat Model
- activos;
- adversarios;
- fronteras de confianza.

### 0.3 Architecture
- módulos;
- pipeline;
- artifacts.

### 0.4 Configuration Spec
- schema;
- profiles;
- selectors.

### 0.5 Security Design
- capas;
- risk engine;
- diversity.

### 0.6 Test Strategy
- correctness;
- compatibility;
- adversarial lab.

### 0.7 Repository structure
Crear workspace y convenciones.

### 0.8 CI baseline
Format, lint, tests, dependency audit.

### 0.9 ADR baseline
Registrar decisiones principales.

### 0.10 Security policy
Proceso de reporte.

Criterio de salida:
- documentación coherente;
- estructura inicial compilable;
- CI verde.

Estado actual: **COMPLETADA**. La fundación quedó validada por GitHub Actions en el run #28 (`37504965228`): `Rust quality` y `RustSec audit` finalizaron correctamente.

---

## Fase A — Core Packaging

### A.1 Rust workspace
### A.2 CLI skeleton
### A.3 ZIP/APK normalizer
### A.4 Manifest inspection
### A.5 Multi-DEX discovery
### A.6 BuildPlan
### A.7 Transactional pipeline
### A.8 Public/private reports
### A.9 apksigner/zipalign integration
### A.10 protect/inspect/verify commands

Criterio:
- tomar APK simple, normalizarlo, reconstruirlo, firmarlo y verificarlo sin modificar semántica.

Estado actual: **COMPLETADA**. Las subfases A.1–A.10 están implementadas. GitHub Actions run #96 (`37512809317`) validó `Rust quality`, `RustSec audit` y el pipeline APK E2E con `zipalign`, firma V1/V2/V3 y `apksigner verify`.

---

## Fase B — DEX Engine

### B.1 DEX parser
### B.2 DEX writer
### B.3 Validation
### B.4 CFG
### B.5 Type analysis
### B.6 SSA/IR
### B.7 Reference graph
### B.8 Selector resolver
### B.9 Rename pass
### B.10 Metadata reduction
### B.11 Reflection/JNI compatibility analysis
### B.12 Multidex rewrite

Criterio:
- golden apps funcionan tras round-trip y renaming compatible.

Estado actual: **COMPLETADA**. Las subfases B.1–B.12 están implementadas y el GitHub Actions run #162 (`37522614748`) validó Rust quality, RustSec, regresión de Phase A y el gate E2E de Phase B con golden DEX, round-trip byte-stable, renaming compatible, metadata reduction y multidex.

---

## Fase C — Data Protection

### C.1 String sensitivity model
### C.2 Authenticated encrypted containers
### C.3 Per-build key derivation
### C.4 Decrypt-on-use runtime
### C.5 Constant protection
### C.6 Resource selection
### C.7 Resource containers
### C.8 Lifetime/caching policies
### C.9 Private metadata
### C.10 Exposure benchmark

Criterio:
- strings críticas no aparecen trivialmente; overhead dentro de presupuesto.

Estado actual: **COMPLETADA**. Las subfases C.1–C.10 están implementadas. GitHub Actions run #216 (`37526352684`) validó Rust quality, RustSec, regresiones de Fases A/B, data protection E2E, rechazo de tampering, ausencia del probe crítico en el contenedor protegido, diversificación por build, presupuesto de overhead y compatibilidad con Rust 1.81.

---

## Fase D — Integrity / Anti-Tamper

### D.1 Certificate binding
### D.2 Package identity
### D.3 DEX regions
### D.4 Resource integrity
### D.5 Native integrity
### D.6 Integrity Graph
### D.7 Distributed checks
### D.8 Response API
### D.9 Re-sign tests
### D.10 Patch/repack tests

Criterio:
- modificaciones definidas por shield-lab se detectan sin un único check central.

Estado actual: **COMPLETADA**. Las subfases D.1–D.10 están implementadas. GitHub Actions PR run #264 (`37542495923`) validó Rust quality, RustSec, regresiones de Fases A/B/C, compatibilidad Rust 1.81, re-firma con dos certificados PKCS12 independientes y rechazo fail-closed de modificaciones DEX, recursos, bibliotecas nativas e identidad de paquete.

---

## Fase E — RASP

### E.1 Signal API
### E.2 Debug evidence
### E.3 Instrumentation evidence
### E.4 Hook/injection evidence
### E.5 Modified-system evidence
### E.6 Emulator evidence
### E.7 Integrity evidence fusion
### E.8 Risk Engine
### E.9 Policy compiler
### E.10 Responses
### E.11 Report-only mode
### E.12 False-positive lab

Criterio:
- correlación estable, políticas auditables y baja tasa de falsos positivos.

Estado actual: **COMPLETADA**. Las subfases E.1–E.12 están implementadas en `nexora-shield-rasp`: señales tipadas, evidencia runtime, integración de integridad, Risk Engine correlacionado, compilador de políticas estricto, respuestas no destructivas, modo report-only y laboratorio determinista de falsos positivos. GitHub Actions run #349 (`37559492616`) validó Rust quality, RustSec, Fases A–D, Phase E RASP E.1–E.12 y compatibilidad Rust 1.81 sin errores.

---

## Fase F — Native Shield

### F.1 Runtime crate/library
### F.2 JNI boundary
### F.3 arm64-v8a
### F.4 x86_64
### F.5 Additional ABI policy
### F.6 Native integrity helpers
### F.7 Generated native data
### F.8 Hardening compiler flags
### F.9 Symbol minimization
### F.10 Native fuzz/tests

Criterio:
- runtime nativo reproducible, estable y modular.

Estado actual: **COMPLETADA**. F.1–F.10 están implementadas. GitHub Actions run #425 (`37562726466`) validó Rust quality, RustSec, regresiones A–E, Phase F host, Rust 1.81 MSRV, enlace Android real para arm64-v8a/x86_64, RELRO/NOW, ausencia de build-id, superficie JNI mínima y reproducibilidad byte a byte.

---

## Fase G — VM Shield

### G.1 Eligibility analyzer
### G.2 VM IR
### G.3 Opcode model
### G.4 Lowering
### G.5 Interpreter
### G.6 Exception semantics
### G.7 Calls/fields
### G.8 Constant pools
### G.9 Per-build opcode allocation
### G.10 Metadata sealing
### G.11 Performance estimator
### G.12 Differential tests
### G.13 Selective annotations/config
### G.14 VM security benchmark

Criterio:
- métodos críticos virtualizados mantienen semántica y muestran diversidad real entre builds.

Estado actual: **COMPLETADA**. G.1–G.14 están implementadas en `nexora-shield-vm`: elegibilidad fail-safe, VM IR, bytecode VM completo con operandos, asignación privada de opcodes por build, lowering DEX selectivo, intérprete, excepciones con asignabilidad delegada al host, calls/fields, constant pool, sellado HMAC del ejecutable, estimación de coste, pruebas diferenciales, selección por configuración/anotación y benchmark estructural de diversidad. GitHub Actions run #584 (`37571516228`) validó Rust quality, RustSec, regresiones A–F, Phase G G.1–G.14, diferencial/security y Rust 1.81 MSRV sin errores.

---

## Fase H — Per-Build Diversification

### H.1 Seed model
### H.2 Reproducible private mode
### H.3 Rename diversity
### H.4 Pass variants
### H.5 CFG variants
### H.6 Integrity graph topology variants
### H.7 String container partition variants
### H.8 VM map variants
### H.9 Native generated constants
### H.10 Cross-build bypass regression

Criterio:
- bypasses/patches basados en offsets/patrones de un build no transfieren de forma trivial.

Estado actual: **COMPLETADA**. H.1–H.10 están implementadas en `nexora-shield-diversity`: seed privada de mínimo 32 bytes con separación HMAC por dominio y zeroization, modo reproducible privado, diversidad de rename, orden de pases, CFG materializado sobre VM IR, topologías válidas de integridad, shards opacos de strings de Phase C, mapas VM, constantes nativas y regresión pairwise de portabilidad entre 32 builds. GitHub Actions run #665 (`37574529544`) validó Rust quality, RustSec, regresiones A–G, H.1–H.10, Rust 1.81 y el gate de portabilidad sin errores.

---

## Fase I — Attestation & Remote Policy

Opcional; no necesaria para apps totalmente offline.

### I.1 Attestation abstraction
### I.2 Nonce/session model
### I.3 Anti-replay
### I.4 Server verification sample
### I.5 Signed policy
### I.6 Build revocation
### I.7 Feature-specific thresholds
### I.8 Offline degradation
### I.9 Privacy docs
### I.10 Integration tests

Criterio:
- decisiones sensibles pueden incorporar evidencia de servidor sin hacer la app inutilizable offline cuando no corresponda.

Estado actual: **EN PROGRESO**. I.1–I.10 cuentan con implementación en `nexora-shield-attestation`: abstracción proveedor/verificador, challenge session/nonce con anti-replay, ejemplo de verificación servidor, política firmada con anti-rollback, revocación de builds, umbrales por feature, degradación offline, contrato de privacidad y pruebas integrales. La fase no se considera cerrada hasta que CI valide Rust 1.81, calidad estricta y regresiones A–H sobre el head final.

---

## Fase J — Gradle Plugin

### J.1 AGP integration
### J.2 Variant API
### J.3 Release-only defaults
### J.4 Config schema completion
### J.5 Secret providers
### J.6 Reports
### J.7 Mapping/retrace
### J.8 Build cache strategy
### J.9 CI examples
### J.10 Sample apps

Criterio:
- una app Android puede activar Nexora Shield sin pipeline manual.

---

## Fase K — AAB / AAR / Splits

### K.1 AAB parser/model
### K.2 bundletool validation
### K.3 Dynamic features
### K.4 Split APK testing
### K.5 Play App Signing compatibility
### K.6 AAR consumer rules
### K.7 Library protection mode
### K.8 Resource namespaces
### K.9 Baseline profiles interaction
### K.10 Publishing tests

---

## Fase L — Shield Studio

### L.1 Compose Multiplatform shell
### L.2 Project import
### L.3 Profile editor
### L.4 Selector editor
### L.5 Security report
### L.6 Performance budget UI
### L.7 Build console
### L.8 Artifact verification
### L.9 Mapping/retrace UI
### L.10 Secure secret-provider integration

Studio nunca reemplaza la CLI; es una capa de UX.

---

## Fase M — Security Lab

### M.1 Static exposure harness
### M.2 Repack harness
### M.3 Re-sign harness
### M.4 Runtime instrumentation lab
### M.5 Modified-environment matrix
### M.6 Automated bypass portability tests
### M.7 Fuzz farm
### M.8 Performance farm
### M.9 Regression corpus
### M.10 Security score
### M.11 Comparative benchmark methodology
### M.12 External audit preparation

Criterio:
- todo bypass conocido entra al corpus y se prueba en cada release.

---

## Fase N — Production Hardening

### N.1 API freeze candidate
### N.2 Config schema stable
### N.3 Migration tooling
### N.4 Documentation audit
### N.5 Supply-chain hardening
### N.6 SBOM/provenance
### N.7 Signed releases
### N.8 Crash/retrace validation
### N.9 Security review
### N.10 Performance review
### N.11 Compatibility review
### N.12 1.0 release candidate
### N.13 External feedback
### N.14 1.0 stable

---

## Después de 1.0

- nuevos VM backends;
- nuevas variantes de transformaciones;
- adaptive policies;
- enterprise KMS;
- team policy management;
- IDE integration;
- additional attestation providers;
- research en hardening de WebView/native;
- benchmarks externos continuos.

## Política de avance

Una fase solo se marca DONE cuando:

- código integrado;
- tests;
- documentación;
- CI;
- criterio de salida cumplido;
- no existe un error crítico conocido de esa fase.

Los subtasks incompletos se mantienen explícitos; no se marca una fase como terminada por porcentaje.
