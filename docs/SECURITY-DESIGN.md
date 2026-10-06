# Security Design

## 1. Meta

Nexora Shield pretende superar el enfoque de un ofuscador tradicional mediante una arquitectura adaptable y multicapa. "Más avanzado que un producto existente" se tratará como una meta medible, no como una afirmación comercial hasta que exista evidencia comparativa reproducible.

## 2. Capas

    L0 Build security
    L1 Symbol/metadata obfuscation
    L2 Data protection
    L3 Control-flow hardening
    L4 Integrity graph
    L5 RASP
    L6 Native shield
    L7 VM shield
    L8 Per-build diversification
    L9 Optional remote attestation/policy

Un perfil puede habilitar un subconjunto, pero Hardened/Maximum debe usar varias capas.

## 3. Obfuscation

### Renaming

- clases;
- métodos;
- fields;
- synthetic wrappers;
- package flattening opcional;
- preservación de reflection cuando sea necesario.

El analizador debe detectar reflection, serialization, JNI y frameworks con nombres contractuales para generar keep rules o advertencias.

### Metadata reduction

Eliminar o minimizar, cuando sea seguro:

- nombres de source file;
- line tables públicas;
- debug locals;
- annotations no requeridas;
- metadata redundante.

Kotlin Metadata requiere tratamiento específico para no romper reflection/serialization.

## 4. Strings y constantes

No se usará una clave global.

Diseño:

- clasificar strings por sensibilidad;
- agrupar por dominio;
- cifrado autenticado;
- derivación per-build;
- decrypt-on-use;
- caché configurable y acotada;
- zeroization best-effort;
- rotación de formatos entre builds.

No se cifrarán indiscriminadamente strings de UI si solo aumentan coste sin beneficio.

## 5. Resource Shield

Objetivos:

- assets propietarios;
- archivos de configuración;
- tablas;
- modelos o blobs.

Estrategias:

- packing selectivo;
- cifrado autenticado;
- nombre/layout diversificado;
- carga mediante runtime mínimo;
- integridad asociada.

Recursos que Android debe leer directamente no pueden ocultarse sin afectar compatibilidad; el planner debe conocer esas restricciones.

## 6. Control-flow hardening

Pases candidatos:

- block splitting;
- branch rewriting;
- opaque state variables;
- dispatcher transformation en métodos seleccionados;
- call indirection;
- synthetic wrapper networks.

Reglas:

- equivalencia semántica verificada;
- no aplicar agresivamente en hot paths;
- limitar crecimiento de bytecode;
- no violar verifier DEX;
- tener variantes per-build.

## 7. Integrity Graph

En lugar de una comprobación central, se genera un grafo.

Ejemplo:

    auth entry ----checks----> cert node
         |                       |
         +----checks----> dex region A
         |
    premium flow --> resource node
         |
    native bridge --> runtime node
         |
    vm entry ------> vm metadata node

Características:

- múltiples raíces;
- checks en Java/Kotlin y native;
- parámetros diversificados;
- hashes/expected values fragmentados;
- comprobaciones periódicas o por operación sensible;
- policy result común.

El grafo se construye después de las transformaciones que cambian el contenido.

## 8. Certificate binding

Nexora Shield debe poder enlazar funciones protegidas con:

- signer esperado;
- lineage de firma cuando proceda;
- identidad del build;
- package/application id.

La validación debe ser compatible con esquemas de firma Android y Play App Signing.

## 9. RASP Signal Model

Cada señal:

    id
    category
    confidence
    severity
    freshness
    evidence_hash
    collector_version

Categorías:

- debugger;
- instrumentation;
- injected/native modules;
- hook frameworks;
- root/system modification;
- emulator;
- package/signature mismatch;
- integrity mismatch;
- memory inconsistency;
- attestation;
- timing anomaly solo como señal débil.

Una señal aislada raramente debe bloquear.

## 10. Risk Engine

Puntuación orientativa:

    risk = weighted evidence + correlation bonuses - trust evidence

Pero la implementación debe usar reglas versionadas, no una suma rígida universal.

Ejemplo de política:

    risk < 25       allow
    25..49          observe
    50..74          require stronger verification
    >=75            protect sensitive operation

La aplicación configura acciones. Nexora Shield no debe introducir cierres inesperados sin consentimiento del integrador.

## 11. Native Shield

Principios:

- varias ABIs;
- símbolos mínimos;
- JNI contract pequeño;
- validación de inputs;
- memory-safe Rust cuando sea práctico;
- C/C++ solo donde sea necesario;
- hardening de compilador;
- separación entre runtime y generated data.

La presencia de native code no se considera por sí sola una protección fuerte.

## 12. VM Shield

La VM protege métodos de máximo valor.

Pipeline:

    DEX IR
      -> eligibility analysis
      -> semantic lowering
      -> VM IR
      -> per-build opcode assignment
      -> metadata sealing
      -> runtime dispatch

Diversificación:

- opcode map;
- operand encoding;
- handler ordering;
- constant pools;
- register mapping;
- dispatch strategy entre variantes seguras.

Limitaciones:

- no virtualizar UI completa;
- no virtualizar métodos extremadamente calientes por defecto;
- interoperabilidad con exceptions cuidadosamente validada;
- reflection/JNI requieren reglas;
- tamaño y tiempo se miden.

## 13. Build Diversity

Cada build puede variar:

- renaming seed;
- transform ordering dentro de dependencias válidas;
- control-flow variants;
- integrity graph topology;
- string container partition;
- VM opcode map;
- wrapper layout;
- native generated constants;
- check placement.

Debe existir reproducibilidad privada mediante seed.

## 14. Secrets

### Nunca confiar únicamente en

- hardcoded API key;
- Base64;
- XOR;
- una clave AES estática embebida;
- un único native function;
- split simple de una clave.

### Estrategias permitidas

Offline:

- minimizar secreto;
- derivación contextual;
- Keystore cuando sea aplicable;
- limitar valor y alcance.

Online:

- secretos efímeros;
- exchange autenticado;
- attestation;
- backend authorization;
- expiración y anti-replay.

## 15. Anti-dump

No se asume que datos descifrados son invisibles. Se reduce la ventana:

- decrypt-on-use;
- buffers pequeños;
- lifetime corto;
- evitar caches globales;
- VM para lógica crítica;
- secretos efímeros del servidor.

## 16. Response Policies

Acciones soportadas:

- record;
- notify host app;
- disable protected operation;
- require login;
- require attestation;
- force online revalidation;
- controlled termination.

No se implementarán acciones destructivas contra el dispositivo ni datos ajenos.

## 17. Remote Policy

Opcional para apps online.

Servidor puede definir:

- minimum shield runtime version;
- blocked compromised build ids;
- required evidence;
- attestation freshness;
- feature-specific risk thresholds.

La política debe estar autenticada y versionada.

## 18. Privacy

RASP puede observar señales sensibles. Diseño:

- recolectar mínimo;
- hashes en lugar de valores cuando baste;
- telemetría opt-in por integrador;
- documentación de cada campo;
- retention configurable;
- no enviar lista completa de apps sin justificación explícita.

## 19. Supply-chain hardening

- dependencias fijadas;
- lockfiles;
- SBOM;
- provenance;
- code review;
- CI sin secretos en forks;
- releases firmados;
- checksums;
- branch protection cuando el proyecto madure.

## 20. Security regression

Todo bypass reproducible se convierte en:

1. caso del shield-lab;
2. regression test;
3. nueva variante o mitigación;
4. entrada de changelog de seguridad cuando sea apropiado.

El objetivo es que el conocimiento adquirido por un atacante envejezca rápido entre builds.

## 21. Criterios para afirmar superioridad

Antes de afirmar públicamente que Nexora Shield supera a otra solución deben existir:

- benchmark definido;
- mismo conjunto de apps;
- mismo threat model;
- mismas herramientas;
- pruebas repetidas;
- métricas de overhead;
- resultados auditables;
- preferiblemente revisión externa.

Hasta entonces la documentación usará "objetivo de diseño" y no "garantía".
