# Configuración

## 1. Objetivo

Nexora Shield usa una configuración declarativa versionada. Ningún secreto debe incluirse directamente en el archivo.

Formato inicial propuesto: YAML.

## 2. Esqueleto

~~~yaml
schema: 1

application:
  id: com.example.app
  minSdk: 24

profile: hardened

build:
  diversity: true
  reproducible: false

selectors:
  sensitive:
    include:
      - com.example.auth.**
      - com.example.billing.**
    exclude:
      - com.example.generated.**

dex:
  rename: true
  metadataReduction: true
  controlFlow:
    enabled: true
    scope: sensitive

crypto:
  strings:
    enabled: true
    scope: sensitive
  constants:
    enabled: true
    scope: sensitive

resources:
  enabled: true
  include:
    - assets/private/**

integrity:
  certificate: true
  dex: true
  resources: true
  native: true

rasp:
  mode: enforce
  policy: policies/release.yml

native:
  enabled: true

vm:
  enabled: true
  scope: critical
  maxMethods: 40

attestation:
  enabled: false

budgets:
  apkGrowthPercent: 20
  startupMs: 80
  buildMinutes: 10
~~~

## 3. Perfiles

### standard

- rename;
- metadata reduction;
- selected string protection;
- certificate integrity;
- basic RASP;
- build diversity.

### hardened

Añade:

- control-flow hardening;
- expanded integrity;
- native runtime;
- resource protection;
- stronger RASP correlation.

### maximum

Añade:

- VM Shield;
- aggressive diversity;
- redundant integrity;
- optional attestation hooks.

Maximum no significa "aplicar todo a todo".

## 4. Selectores

Tipos:

- glob de package/class;
- method signature;
- annotation;
- explicit labels;
- generated source detection;
- hot path exclusions.

Prioridad:

1. explicit exclude;
2. compatibility exclude;
3. critical;
4. sensitive;
5. default profile.

## 5. Tags

La app podrá marcar elementos:

~~~kotlin
@ShieldSensitive
class LicenseVerifier

@ShieldVirtualize
fun verifyEntitlement(...)

@ShieldKeepName
class ReflectionModel
~~~

Las annotations pueden eliminarse del artefacto final cuando ya hayan cumplido su función.

## 6. RASP Policy

~~~yaml
version: 1

signals:
  debugger:
    weight: 25
  instrumentation:
    weight: 45
  signatureMismatch:
    weight: 100
  integrityMismatch:
    weight: 100
  root:
    weight: 15
  emulator:
    weight: 10

responses:
  - when: risk >= 50
    action: require_verification
  - when: risk >= 80
    action: block_sensitive_operation
~~~

Los pesos son específicos de la aplicación; no se usará un default agresivo universal.

## 7. Secrets providers

Configuración referencia IDs:

~~~yaml
secrets:
  provider: env
  signingKeyRef: NEXORA_SIGNING_KEY
  buildSeedRef: NEXORA_BUILD_SEED
~~~

Providers previstos:

- environment;
- file descriptor;
- CI secret provider;
- OS keychain;
- external KMS futuro.

## 8. Reproducibilidad

~~~yaml
build:
  diversity: true
  reproducible: true
  seedRef: RELEASE_4_0_SEED
~~~

Solo para investigación y reproducir errores. No reutilizar la misma seed entre releases normales.

## 9. Budgets

El planner debe estimar y el verifier medir:

~~~yaml
budgets:
  apkGrowthPercent: 15
  startupMsP50: 60
  startupMsP95: 120
  memoryMb: 20
  vmMethods: 25
~~~

Política ante exceso:

~~~yaml
budgetsPolicy: fail
~~~

Opciones futuras: fail, warn, adaptive. Adaptive nunca se habilitará implícitamente en releases estrictos.

## 10. Compatibilidad

~~~yaml
compatibility:
  reflection:
    autoDetect: true
  serialization:
    keepModels: true
  jni:
    autoDetect: true
  compose:
    enabled: true
~~~

## 11. Reportes

~~~yaml
reports:
  public:
    path: build/reports/nexora-shield/report.json
  private:
    enabled: true
    path: private/build-manifest.nshield
~~~

El private report no debe publicarse como artifact público.

## 12. Firma

Nexora Shield recibirá referencias a material de firma, nunca contraseñas hardcoded.

~~~yaml
signing:
  mode: external
  keystoreRef: ANDROID_KEYSTORE_PATH
  aliasRef: ANDROID_KEY_ALIAS
  storePasswordRef: ANDROID_KEYSTORE_PASSWORD
  keyPasswordRef: ANDROID_KEY_PASSWORD
~~~

## 13. Validation

Antes de proteger:

- schema válido;
- selectores resuelven;
- secretos disponibles;
- profile compatible;
- presupuestos coherentes;
- minSdk soportado.

Después:

- DEX verifier;
- package verifier;
- signature verification;
- runtime smoke test en CI cuando esté habilitado.

## 14. Config schema

El proyecto mantendrá un JSON Schema generado para IDE completion y validación. Cambios breaking incrementan schema version.
