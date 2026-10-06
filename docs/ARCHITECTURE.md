# Arquitectura de Nexora Shield

## 1. Propósito

Este documento define la arquitectura técnica de Nexora Shield, una plataforma de hardening y RASP para Android. El sistema debe proteger aplicaciones sin alterar su comportamiento funcional, mantener trazabilidad de cada transformación y permitir que las capas de seguridad evolucionen de forma independiente.

La arquitectura se diseña bajo cuatro restricciones:

1. El atacante controla el dispositivo y puede observar la aplicación en ejecución.
2. No existe una capa individual infalible.
3. Las transformaciones deben ser verificables y reversibles únicamente mediante material privado de build cuando sea necesario para depuración.
4. La protección no puede depender de ocultar una sola clave, función o detector.

## 2. Vista de alto nivel

    Input
      |
      +-- APK
      +-- AAB
      +-- AAR
      +-- Android Gradle variant
      |
      v
    Normalizer
      |
      v
    Program Model
      |
      +--> DEX IR ---------> Transform Passes
      |                         |
      |                         +--> Rename
      |                         +--> CFG hardening
      |                         +--> Constant/string protection
      |                         +--> Call indirection
      |                         +--> VM candidate lowering
      |
      +--> Resources ------> Resource Shield
      |
      +--> Native libs ----> Native Shield
      |
      +--> Manifest -------> Runtime/Provider integration
      |
      v
    Integrity Graph Builder
      |
      v
    RASP Policy Compiler
      |
      v
    Repack / Bundle rebuild
      |
      v
    Validate -> Align -> Sign
      |
      v
    Protected artifact + private build manifest + public report

## 3. Módulos

### shield-core

Responsable de:

- cargar configuración;
- descubrir inputs;
- crear un BuildPlan inmutable;
- ejecutar pases en orden;
- coordinar artefactos;
- aplicar rollback si falla una fase;
- generar reportes;
- imponer presupuestos y compatibilidad.

shield-core no debe contener lógica específica de DEX ni detecciones RASP.

### shield-package

Abstrae APK/AAB/AAR y ZIP. Debe:

- validar estructura;
- conservar metadatos necesarios;
- normalizar entradas;
- detectar archivos duplicados o ambiguos;
- manejar assets, resources.arsc y manifest;
- reconstruir sin corromper alignment;
- producir manifests de contenido.

### shield-dex

Submódulos previstos:

- dex-reader;
- dex-writer;
- dex-validator;
- dex-ir;
- cfg;
- ssa;
- type-analysis;
- reference-graph;
- transform-api;
- transform-passes.

El IR debe desacoplar los pases de la representación binaria DEX. Cada pase declara:

- precondiciones;
- invariantes;
- efectos;
- coste estimado;
- compatibilidad;
- metadatos requeridos;
- capacidad de rollback.

### shield-crypto

No inventará primitivas criptográficas. Usará bibliotecas revisadas y algoritmos estándares. Responsabilidades:

- derivación de claves por dominio;
- wrapping de material de build;
- cifrado autenticado de blobs;
- generación segura de seeds;
- separación de claves por aplicación/build/capa;
- API de zeroization donde la plataforma lo permita;
- integración opcional con Android Keystore/StrongBox y backend.

### shield-integrity

Construye un grafo de integridad distribuido. Los nodos pueden representar:

- certificado esperado;
- DEX sections;
- tablas internas;
- recursos críticos;
- librerías nativas;
- manifiesto;
- código virtualizado;
- configuración RASP.

No debe existir un único "if tampered" central. Las comprobaciones se distribuyen y se correlacionan.

### shield-rasp

Incluye:

- Signal API;
- collectors;
- evidence normalization;
- risk engine;
- policy evaluator;
- response adapters;
- optional telemetry interface.

Los collectors no deben decidir la respuesta final. Solo producen evidencia normalizada con confianza, timestamp y origen.

### shield-native

Runtime nativo para:

- comprobaciones seleccionadas;
- integridad de código/memoria;
- apoyo al VM runtime;
- bridges JNI;
- operaciones de coste alto que no conviene mantener en Kotlin.

El código nativo es una capa adicional, no una "zona secreta".

### shield-vm

Virtualiza únicamente métodos seleccionados. Componentes:

- eligibility analyzer;
- lowering desde IR;
- bytecode generator;
- per-build opcode allocator;
- interpreter/runtime;
- metadata encryptor;
- performance estimator;
- verifier.

### shield-diversify

Gestiona mutación por build:

- seed;
- variantes de pases;
- nombres;
- layouts;
- orden seguro;
- parámetros de cifrado;
- mapping de opcodes VM;
- scheduling de checks;
- build fingerprint privado.

### shield-gradle-plugin

Integra Nexora Shield con Android Gradle Plugin. Debe:

- descubrir variants;
- respetar build types/flavors;
- proteger solo release por defecto;
- aceptar configuración versionada;
- producir reportes;
- trabajar con configuración cacheable cuando sea posible;
- no almacenar secretos en build.gradle.

### shield-cli

Interfaz para CI y uso standalone:

- protect;
- inspect;
- verify;
- explain-config;
- retrace;
- benchmark;
- doctor.

### shield-studio

Interfaz visual futura. No contendrá lógica de seguridad propia: llamará al core mediante una API estable.

### shield-lab

Entorno de pruebas adversariales. Ejecutará pruebas controladas contra artefactos propios para detectar regresiones de protección.

## 4. BuildPlan

Antes de modificar un artefacto, shield-core genera un plan completo.

Campos conceptuales:

    build_id
    schema_version
    input_fingerprint
    target_profile
    seed_reference
    transforms[]
    selectors[]
    runtime_features[]
    integrity_nodes[]
    signing_plan
    performance_budget
    compatibility_flags

El BuildPlan se congela antes de la ejecución. Si una fase necesita cambiarlo debe provocar una nueva planificación para evitar builds parcialmente explicables.

## 5. Pipeline transaccional

Cada fase produce una salida temporal y un resultado de validación.

Estados:

    PLANNED
      -> NORMALIZED
      -> ANALYZED
      -> TRANSFORMED
      -> RUNTIME_INJECTED
      -> INTEGRITY_BOUND
      -> REBUILT
      -> VALIDATED
      -> SIGNED
      -> VERIFIED

Un fallo no debe marcar el build como protegido. Solo VERIFIED produce un artefacto publicable.

## 6. DEX IR

El IR debe soportar:

- múltiples classes.dex;
- control-flow graph;
- exception edges;
- invoke-polymorphic/custom cuando aplique;
- annotations;
- debug metadata opcional;
- synthetic methods;
- desugared bytecode;
- Kotlin metadata preservable según configuración;
- validación de registers y types.

Las transformaciones no pueden asumir Java source equivalente.

## 7. Sistema de pases

Categorías:

### Structural
Renombrado, reordenamiento seguro, synthetic indirection.

### Data protection
Strings, constantes, tablas, blobs y metadatos.

### Control-flow
Transformaciones que dificultan análisis estático manteniendo equivalencia semántica.

### Integrity injection
Inserción de probes y enlaces al grafo de integridad.

### VM lowering
Selección y conversión de métodos elegibles.

### Cleanup
Dead metadata removal, compactación y reparación de referencias.

Cada pase debe ser idempotente o declarar explícitamente que no lo es.

## 8. Selectores

La protección se decide mediante selectores combinables:

- package;
- class;
- method signature;
- annotation;
- visibility;
- source set;
- estimated hotness;
- explicit sensitivity tag.

Ejemplo conceptual:

    protect:
      include:
        - "com.nexora.player.auth.**"
        - "@Sensitive"
      exclude:
        - "androidx.**"
        - "kotlin.**"

## 9. Runtime mínimo

El runtime debe ser modular. Una aplicación solo recibe los módulos requeridos por su perfil. Esto reduce:

- tamaño;
- superficie de bugs;
- coste de inicio;
- falsos positivos.

El runtime tendrá una API interna versionada y un protocolo de evidencia estable.

## 10. Firma y packaging

La primera versión utilizará herramientas oficiales Android para firma y validación. No se implementará un firmador criptográfico propio hasta que exista una razón y auditoría suficiente.

APK:

- rebuild;
- zipalign;
- apksigner;
- apksigner verify;
- instalación smoke test.

AAB:

- preservar modelo de bundle;
- validar con bundletool;
- generar APK set de prueba;
- comprobar instalación;
- respetar Play App Signing.

V4 se tratará como artefacto complementario .idsig cuando corresponda; no se confundirá con V1/V2/V3.

## 11. Material privado de build

Artefactos privados:

- mapping de símbolos;
- VM opcode map;
- seed o referencia protegida a seed;
- integrity manifest;
- retrace metadata;
- transform manifest.

Nunca se incrustan completos en el APK final. CI debe permitir su almacenamiento cifrado y con retención configurable.

## 12. Reproducibilidad controlada

Por defecto dos builds usan seeds diferentes. Para depurar una regresión se podrá reconstruir con una seed privada y configuración idéntica.

Requisitos:

- registrar versión exacta de Nexora Shield;
- registrar versión de AGP/Build Tools;
- registrar hash del input;
- mantener transform manifest;
- no depender de timestamps no controlados en transformaciones.

## 13. Presupuestos

Cada perfil define límites máximos:

- incremento de APK/AAB;
- startup overhead;
- CPU en hot path;
- memoria;
- tiempo de build;
- número de métodos virtualizados.

Si el plan excede el presupuesto debe fallar o degradar explícitamente según política. Nunca degradará silenciosamente.

## 14. Compatibilidad

Matriz inicial:

- minSdk 24;
- Android 7 a Android 16;
- arm64-v8a prioritario;
- armeabi-v7a y x86_64 según fase;
- multidex;
- Kotlin/Java;
- Compose;
- R8;
- JNI;
- App Bundles.

## 15. Extensibilidad

La API de transformaciones tendrá versionado semántico interno. Un plugin de transformación debe declarar capacidades y no podrá acceder directamente a secretos de otras capas.

## 16. Observabilidad

El build genera dos reportes:

### Public Security Report
Seguro para CI logs. Incluye:

- features habilitadas;
- cobertura porcentual;
- overhead estimado;
- warnings;
- compatibilidad.

### Private Build Report
Contiene material sensible de trazabilidad. Debe almacenarse como artefacto restringido.

## 17. Decisiones que requieren ADR

Se documentarán Architecture Decision Records para:

- IR interno;
- estrategia de firma;
- runtime native language;
- VM design;
- formato del private build manifest;
- integración AGP;
- política de attestation;
- telemetría.

## 18. Regla de arquitectura

Ninguna capa puede asumir que otra es imposible de romper. Cada capa debe seguir aportando valor cuando una capa vecina sea neutralizada.
