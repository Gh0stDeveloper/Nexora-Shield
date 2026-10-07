# Testing Strategy

## 1. Filosofía

Una herramienta de protección puede compilar y aun así ser inútil o romper la app. Nexora Shield requiere cuatro dimensiones de prueba:

1. Correctness.
2. Compatibility.
3. Performance.
4. Adversarial resistance.

Una release falla si cualquiera de las cuatro queda fuera de criterio.

## 2. Unit tests

Cobertura obligatoria para:

- DEX parser/writer;
- CFG;
- type analysis;
- instruction encoding;
- string containers;
- crypto wrappers;
- configuration;
- selector engine;
- integrity graph;
- risk policy;
- VM assembler/interpreter.

## 3. Property tests

Propiedades:

- parse(write(parse(x))) conserva semántica estructural;
- transformaciones no generan referencias inválidas;
- string encryption round-trip;
- integrity manifest determinista con seed fija;
- VM lowering conserva outputs en casos generados.

## 4. Fuzzing

Targets iniciales:

- DEX reader;
- DEX writer;
- manifest parser;
- resource container parser;
- config parser;
- VM bytecode verifier;
- private manifest parser.

Resultados que causen panic/crash se guardan como corpus de regresión.

## 5. Golden apps

Repositorio de aplicaciones de prueba:

- Java simple;
- Kotlin;
- Compose;
- multidex;
- reflection;
- serialization;
- JNI;
- coroutines;
- Room;
- Media3;
- app con múltiples flavors;
- AAB dynamic features cuando se soporte.

Cada golden app tiene tests funcionales antes y después de protección.

## 6. Android matrix

Mínimo inicial:

- Android 7 / API 24;
- Android 8;
- Android 10;
- Android 12;
- Android 14;
- Android 15;
- Android 16.

Dispositivos/emuladores deben incluir:

- arm64;
- x86_64 para CI;
- al menos dispositivos físicos stock;
- dispositivos de laboratorio modificados para RASP testing.

## 7. Packaging tests

APK:

- install;
- launch;
- upgrade over previous protected build;
- uninstall/reinstall;
- signature verification;
- split compatibility cuando aplique.

AAB:

- bundle validate;
- generate apks;
- universal APK smoke;
- device-targeted APK set;
- Play Signing compatibility documented.

## 8. Adversarial Lab

shield-lab probará artefactos propios con herramientas conocidas para medir exposición.

Categorías:

### Static visibility
- decompilation quality;
- symbol recovery;
- plaintext strings;
- resource extraction;
- control-flow simplification.

### Tamper
- byte modification;
- manifest modification;
- re-sign;
- resource replacement;
- method patching.

### Runtime
- debugger;
- instrumentation;
- hooks;
- modified environment;
- memory observation.

### Automation resistance
Un bypass válido para Build A se prueba contra Build B/C con seeds distintas. La tasa de transferencia debe ser una métrica explícita.

El laboratorio no debe ejecutar pruebas sobre aplicaciones de terceros sin autorización.

## 9. Scoring interno

Ejemplo:

| Métrica | Weight |
|---|---:|
| Repackaging detection | 20 |
| Re-sign detection | 15 |
| Sensitive string exposure | 10 |
| Critical method readability | 15 |
| Runtime instrumentation evidence | 15 |
| Build diversity | 10 |
| VM coverage | 5 |
| False positive rate | 5 |
| Performance budget | 5 |

El score sirve para regresión interna, no como certificado absoluto de seguridad.

## 10. Performance

Medir:

- build time;
- APK/AAB growth;
- cold start;
- warm start;
- CPU;
- memory;
- method latency;
- VM overhead;
- RASP polling/event cost.

Perfiles tienen SLO propios.

## 11. Correctness gate

Antes de release:

- 100% parser/writer critical suite;
- no verifier errors;
- no crash en golden apps;
- instalación en matriz;
- signing verification;
- retrace round-trip;
- private artifacts no presentes en package.

## 12. Security gate

Antes de release:

- anti-tamper suite;
- re-sign suite;
- RASP suite;
- string exposure threshold;
- build diversity threshold;
- bypass regression corpus;
- no known critical generic bypass.

## 13. False-positive gate

RASP se prueba en:

- stock;
- developer mode;
- USB debugging;
- emulators;
- rooted test devices;
- OEM variants cuando haya recursos.

Signals no equivalen automáticamente a block.

## 14. Differential testing

Para cada transformación:

1. ejecutar input sin proteger;
2. ejecutar protegido;
3. comparar outputs funcionales;
4. comparar excepciones;
5. comparar persistencia;
6. repetir con seeds distintas.

## 15. VM differential tests

Para métodos soportados por la versión actual:

- salida de referencia vs VM;
- límites de enteros de 32 bits;
- wrapping arithmetic;
- miles de inputs deterministas;
- branches;
- exceptions;
- calls/fields mediante host de prueba;
- mapas de opcode con seeds/build ids distintos.

Los tipos u opcodes todavía no soportados —por ejemplo float/arrays/synchronization en la primera implementación de Phase G— deben ser rechazados por elegibilidad y no simulados de forma aproximada.

Además, el security benchmark de VM exige diversidad estructural entre builds y el metadata seal debe rechazar payloads modificados o claves incorrectas.

## 16. Release channels

### nightly
Puede contener funciones experimentales.

### beta
Todas las funciones nuevas con security-lab.

### stable
Solo features que pasan correctness, performance, compatibility y security gates.

## 17. Evidence

Cada CI release guarda:

- test summary;
- security score;
- performance diff;
- config schema;
- SBOM;
- provenance;
- checksum;
- shield version.

Material privado se almacena en un canal separado.
