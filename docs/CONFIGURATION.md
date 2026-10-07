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
  diversityMode: unique_build
  seedRef: NEXORA_BUILD_SEED
  buildNonceRef: NEXORA_BUILD_NONCE
  renameDiversity: true
  passVariants: true
  cfgVariants: true
  integrityTopologyVariants: true
  stringPartitions:
    min: 2
    max: 5
  vmMapVariants: true
  nativeGeneratedConstants: true
  maxCrossBuildTransferBasisPoints: 3000

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
  mode: config_or_annotation
  annotationDescriptor: Ldev/nexora/shield/Virtualize;
  selectors:
    - classPattern: Lcom/example/auth/*;
      methodPattern: verify*
  eligibility:
    maxRegisters: 128
    maxInstructions: 4096
    allowCalls: true
    allowFields: true
    allowExceptions: true
  opcodeDiversification: true
  metadataSealing: true
  maxRelativeCostBasisPoints: 80000

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

## 8. VM Shield

Phase G virtualiza únicamente métodos seleccionados que también pasen el analizador de elegibilidad.

~~~yaml
vm:
  enabled: true
  mode: config_or_annotation
  annotationDescriptor: Ldev/nexora/shield/Virtualize;
  selectors:
    - classPattern: Lcom/example/auth/*;
      methodPattern: verify*
  eligibility:
    maxRegisters: 128
    maxInstructions: 4096
    allowCalls: true
    allowFields: true
    allowExceptions: true
  opcodeDiversification: true
  metadataSealing: true
  maxRelativeCostBasisPoints: 80000
~~~

Modos de selección:

- `config_only`;
- `annotation_only`;
- `config_or_annotation`;
- `config_and_annotation`.

La selección y la elegibilidad son gates separados. Un método marcado para virtualización permanece en DEX normal si usa una construcción que la versión actual del VM no puede preservar con seguridad.

`maxRelativeCostBasisPoints` es un presupuesto de estimación estática. No reemplaza benchmarks en dispositivos.

Las semillas privadas para asignación de opcodes y las claves de sellado no se incluyen directamente en esta sección; deben llegar desde el sistema de secretos/build manifest privado.

## 9. Secrets providers

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

## 10. Per-Build Diversification

Phase H usa una seed privada raíz con separación HMAC por dominio. El archivo de configuración contiene únicamente referencias a secretos, nunca la seed ni el nonce reales.

Build normal:

~~~yaml
build:
  diversity: true
  reproducible: false
  diversityMode: unique_build
  seedRef: NEXORA_BUILD_SEED
  buildNonceRef: NEXORA_BUILD_NONCE
  renameDiversity: true
  passVariants: true
  cfgVariants: true
  integrityTopologyVariants: true
  stringPartitions:
    min: 2
    max: 5
  vmMapVariants: true
  nativeGeneratedConstants: true
  maxCrossBuildTransferBasisPoints: 3000
~~~

El proveedor de secretos debe entregar una seed privada de al menos 32 bytes y un nonce nuevo para cada build normal.

Modo reproducible privado:

~~~yaml
build:
  diversity: true
  reproducible: true
  diversityMode: reproducible_private
  seedRef: RELEASE_4_0_SEED
  reproductionId: release-4.0.0-incident-17
~~~

Para reproducir exactamente un build deben coincidir seed privada, application id, build id y reproduction id. Este modo se reserva para incidentes, retrace y reconstrucciones controladas.

Las superficies diversificadas son independientes: rename, orden de pases, CFG, topología de integridad, particiones de strings, mapa VM y constantes nativas. La misma salida derivada no se reutiliza entre dominios.

`maxCrossBuildTransferBasisPoints` define el presupuesto del regression gate de H.10; 3000 equivale a un máximo observado del 30 % de superficies idénticas en cualquier par del corpus.

## 11. Reproducibilidad

La reproducibilidad de Phase H es privada y explícita. No existe un modo público o sin seed que permita reconstruir las decisiones de diversificación.

No reutilizar la misma combinación seed/contexto entre releases normales.

## 12. Budgets

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

## 13. Compatibilidad

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

## 14. Reportes

~~~yaml
reports:
  public:
    path: build/reports/nexora-shield/report.json
  private:
    enabled: true
    path: private/build-manifest.nshield
~~~

El private report no debe publicarse como artifact público.

## 15. Firma

Nexora Shield recibirá referencias a material de firma, nunca contraseñas hardcoded.

~~~yaml
signing:
  mode: external
  keystoreRef: ANDROID_KEYSTORE_PATH
  aliasRef: ANDROID_KEY_ALIAS
  storePasswordRef: ANDROID_KEYSTORE_PASSWORD
  keyPasswordRef: ANDROID_KEY_PASSWORD
~~~

## 16. Validation

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

## 17. Config schema

El proyecto mantendrá un JSON Schema generado para IDE completion y validación. Cambios breaking incrementan schema version.
