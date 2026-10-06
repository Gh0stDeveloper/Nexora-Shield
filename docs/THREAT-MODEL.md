# Threat Model

## 1. Objetivo

Nexora Shield protege aplicaciones Android contra ingeniería inversa, manipulación, redistribución y análisis dinámico. El threat model asume un adversario capaz de controlar el dispositivo donde se ejecuta la aplicación.

La meta no es prometer invulnerabilidad. La meta es elevar coste, tiempo y conocimiento necesarios; impedir ataques triviales; detectar alteraciones; limitar reutilización de bypasses y proteger activos de alto valor mediante varias capas independientes.

## 2. Activos

### Código y lógica

- algoritmos propietarios;
- validaciones de negocio;
- reglas de licencia;
- lógica premium;
- autenticación;
- protocolos internos;
- lógica antifraude;
- integraciones con backend.

### Datos embebidos

- endpoints no públicos;
- constantes sensibles;
- identificadores;
- tablas;
- assets licenciados;
- configuraciones internas.

### Identidad del artefacto

- package name;
- certificado;
- firma;
- versión;
- hashes;
- procedencia del build.

### Confianza runtime

- integridad del proceso;
- ausencia de modificaciones no autorizadas;
- evidencia de attestation;
- política de riesgo.

### Operación

- capacidad de diagnosticar crashes;
- mapping de símbolos;
- seeds;
- metadatos privados de build.

## 3. Adversarios

### T0 — Usuario casual
Usa APK editors, patchers o herramientas preconfiguradas sin comprender DEX.

### T1 — Reverse engineer básico
Conoce JADX, apktool, smali, firmas y modificaciones simples.

### T2 — Analista dinámico
Usa debugger, instrumentation y hooking en laboratorio controlado.

### T3 — Reverse engineer avanzado
Comprende DEX, JNI, native libraries, loaders y puede automatizar parches.

### T4 — Equipo especializado
Dispone de tiempo, tooling propio, análisis diferencial entre versiones y capacidad de instrumentar el sistema.

### T5 — Adversario con control profundo del sistema
Controla kernel/hypervisor o una plataforma equivalente. Nexora Shield solo puede aumentar coste frente a este nivel; no puede establecer una raíz de confianza puramente local.

## 4. Supuestos

- El atacante puede obtener el APK/AAB resultante.
- Puede ejecutar copias de la aplicación repetidamente.
- Puede observar memoria y comportamiento si controla suficientemente el dispositivo.
- Puede re-firmar APK modificados.
- Puede comparar varias versiones.
- Puede bloquear red.
- Puede falsear algunas señales locales.
- Puede automatizar un bypass conocido.

Por tanto, ninguna decisión crítica de backend debe depender exclusivamente de una señal local.

## 5. Fronteras de confianza

    Git repository
         |
         v
    Trusted CI
         |
         v
    Nexora Shield build
         |
         +--> private build artifacts [trusted storage]
         |
         v
    Signed artifact
         |
         v
    User device [hostile/partially trusted]
         |
         v
    Optional backend [trusted boundary]

El dispositivo se considera hostil. Android Keystore/StrongBox puede mejorar la raíz local, pero no se trata como una garantía universal.

## 6. Amenazas principales

| Amenaza | Objetivo del atacante | Respuesta de diseño |
|---|---|---|
| Decompilation | recuperar lógica legible | obfuscation, CFG hardening, VM selectiva |
| String extraction | encontrar secretos/endpoints | string/constant protection |
| Repackaging | modificar y redistribuir | signature + integrity graph |
| Re-signing | reemplazar certificado | certificate binding |
| Static patching | saltar checks | checks distribuidos + diversidad |
| Dynamic hooking | alterar métodos en runtime | RASP + native evidence + risk engine |
| Debugging | observar estados internos | señales anti-debug + políticas |
| Runtime dumping | extraer código/datos ya descifrados | short-lived material + VM + segmentation |
| Framework injection | instrumentar proceso | evidence collectors y correlación |
| Rooted environment | mayor control del dispositivo | señal de riesgo, no bloqueo absoluto |
| Emulator analysis | automatizar análisis | señal contextual |
| Resource theft | extraer assets críticos | cifrado selectivo/packing |
| API replay | reutilizar credenciales | backend nonce/attestation cuando aplique |
| Differential analysis | comparar builds | per-build diversification |
| Automated unpacker | aplicar receta repetible | estructuras/semillas variables |
| Mapping theft | recuperar símbolos | almacenamiento privado separado |

## 7. No-objetivos

Nexora Shield no promete:

- proteger un secreto estático para siempre si debe ser usado totalmente offline;
- derrotar indefinidamente a un adversario con control total del kernel;
- sustituir autenticación/authorization del backend;
- corregir vulnerabilidades de la aplicación;
- convertir criptografía débil de la aplicación en criptografía segura;
- impedir screenshots globalmente en todos los escenarios;
- hacer seguro un endpoint público por ocultar su URL;
- garantizar que ninguna herramienta reconocerá la existencia del protector.

## 8. Invariantes

1. Un APK re-firmado no debe ser indistinguible del original para las funciones protegidas.
2. La desactivación de un collector RASP no debe neutralizar todo el sistema.
3. Un bypass específico no debe repetirse automáticamente entre builds cuando diversity está habilitado.
4. Ningún secreto de backend de alto valor debe depender solo de estar cifrado dentro del APK.
5. Un fallo de protección durante build debe impedir publicar un artefacto etiquetado como protegido.
6. El mapping privado nunca debe empaquetarse por error.
7. Los módulos críticos deben poder operar sin telemetría.
8. Las respuestas RASP deben ser configurables y auditables.

## 9. Estrategia frente a bypasses

Se asume que existirán bypasses. La estrategia es reducir su vida útil:

- cambios por build;
- checks distribuidos;
- señales redundantes;
- selección variable de rutas;
- VM por build;
- actualización rápida de collectors;
- tests de regresión para bypasses conocidos;
- rotación de políticas remotas en apps online.

Cuando se descubre un bypass, debe convertirse en un caso de prueba del shield-lab.

## 10. Severidad

### Critical
Permite desactivar de forma genérica la protección de todas las apps/builds o expone secretos privados de build.

### High
Permite reempaquetar o neutralizar una capa principal de forma reproducible.

### Medium
Reduce una capa concreta, produce falsos negativos significativos o expone información útil.

### Low
Fingerprinting, información secundaria o degradaciones sin bypass.

## 11. Riesgos de falsos positivos

Root, emulación o debugging pueden ser legítimos. Por ello:

- no se bloquean automáticamente por defecto;
- se combinan señales;
- la aplicación puede elegir response policy;
- las señales deben tener confidence;
- se mantiene modo report-only;
- se prueban dispositivos reales modificados y stock.

## 12. Attestation

Para apps con backend, attestation añade una señal externa. Debe usarse como parte de una política, no como única decisión. Se diseñará con:

- nonces;
- caducidad;
- anti-replay;
- binding a sesión;
- políticas del servidor;
- degradación controlada cuando el servicio no esté disponible.

## 13. Protección de la cadena de build

Amenazas adicionales:

- robo de keystore;
- compromiso de CI;
- dependencia maliciosa;
- publicación de mapping;
- seed reuse;
- logs con secretos.

Mitigaciones:

- secret manager;
- permisos mínimos;
- dependency pinning;
- SBOM;
- provenance;
- separación de artefactos públicos/privados;
- scanning de logs;
- firma y verificación en CI.

## 14. Métrica de seguridad

No se usará "protección detectada" como métrica. Se medirán:

- cobertura de superficies sensibles;
- tiempo hasta obtener lógica útil;
- porcentaje de strings recuperables;
- capacidad de reempaquetado;
- resistencia a bypass reutilizable;
- número de capas independientes que un ataque debe neutralizar;
- overhead;
- tasa de falsos positivos;
- regresiones detectadas por shield-lab.
