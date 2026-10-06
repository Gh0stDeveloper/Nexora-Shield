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
  enabled: true
  algorithm: xchacha20poly1305-hkdf-sha256-v1
  rootKeyRef: NEXORA_DATA_ROOT
  stringThreshold: sensitive
  forceProtect:
    - auth.client.secret
  forcePublic:
    - ui.public.label
  cache:
    mode: bounded
    maxEntries: 32
    maxBytes: 262144
    ttlSeconds: 30
  exposureMaxOverheadPercent: 10

resources:
  dataProtection: true
  include:
    - assets/private/*
    - res/raw/*
  exclude:
    - assets/public/*
  maxResourceBytes: 67108864
  allowAssets: true
  allowResRaw: true

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

## 7. Data Protection

Phase C uses authenticated encryption and explicit secret references. Raw cryptographic root material must never be committed to YAML/JSON.

~~~yaml
crypto:
  enabled: true
  algorithm: xchacha20poly1305-hkdf-sha256-v1
  rootKeyRef: NEXORA_DATA_ROOT
  stringThreshold: sensitive
  forceProtect:
    - auth.client.secret
  forcePublic:
    - ui.public.label
  cache:
    mode: disabled
  exposureMaxOverheadPercent: 10
~~~

`rootKeyRef` identifies an external 32-byte root secret. The current CLI provider expects the referenced environment variable to contain 64 hexadecimal characters. The raw value is not accepted as a command-line option and is not written to private metadata.

Available string thresholds:

- `internal`;
- `sensitive`;
- `critical`.

The default runtime cache policy is `disabled`. A bounded cache must specify all limits explicitly:

~~~yaml
cache:
  mode: bounded
  maxEntries: 32
  maxBytes: 262144
  ttlSeconds: 30
~~~

Resource protection is conservative because many Android resources are loaded directly by the framework:

~~~yaml
resources:
  dataProtection: true
  include:
    - assets/private/*
    - res/raw/*
  exclude:
    - assets/public/*
  maxResourceBytes: 67108864
  allowAssets: true
  allowResRaw: true
~~~

Android contract resources, DEX files, native libraries, signing metadata and framework-loaded resource classes are excluded by the Phase C selector even if a broad pattern would otherwise make them attractive targets.

The public protected resource bundle contains opaque IDs rather than plaintext logical paths. Logical-to-opaque mappings belong only in the private build metadata.

## 8. Secrets providers

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

## 9. Reproducibilidad

~~~yaml
build:
  diversity: true
  reproducible: true
  seedRef: RELEASE_4_0_SEED
~~~

Solo para investigación y reproducir errores. No reutilizar la misma seed entre releases normales.

## 10. Budgets

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

## 11. Compatibilidad

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

## 12. Reportes

~~~yaml
reports:
  public:
    path: build/reports/nexora-shield/report.json
  private:
    enabled: true
    path: private/build-manifest.nshield
~~~

El private report no debe publicarse como artifact público.

## 13. Firma

Nexora Shield recibirá referencias a material de firma, nunca contraseñas hardcoded.

~~~yaml
signing:
  mode: external
  keystoreRef: ANDROID_KEYSTORE_PATH
  aliasRef: ANDROID_KEY_ALIAS
  storePasswordRef: ANDROID_KEYSTORE_PASSWORD
  keyPasswordRef: ANDROID_KEY_PASSWORD
~~~

## 14. Validation

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

## 15. Config schema

El proyecto mantendrá un JSON Schema generado para IDE completion y validación. Cambios breaking incrementan schema version.
