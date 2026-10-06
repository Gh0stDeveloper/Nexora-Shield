# Nexora Shield

Nexora Shield es una plataforma de protección avanzada para aplicaciones Android. Su objetivo es elevar de forma drástica el coste de ingeniería inversa, manipulación, reempaquetado, instrumentación y extracción de lógica sensible mediante una defensa multicapa: transformación DEX, cifrado selectivo, integridad, RASP, protección nativa, diversificación por compilación y, para métodos de alto valor, virtualización.

> Estado: **Fase 0 — Foundation implementada**. El workspace, contratos iniciales, esquema de configuración, CI, ADRs, threat model y política de seguridad ya están establecidos. La siguiente fase de implementación es **Fase A — Core Packaging**. El proyecto todavía no debe anunciarse como "imposible de romper": ninguna protección ejecutada en un dispositivo controlado por un atacante puede garantizar invulnerabilidad absoluta.

## Objetivos

- Proteger APK, AAB y AAR sin exigir cambios invasivos en la aplicación.
- Integrarse mediante CLI y Gradle Plugin.
- Mantener compatibilidad con Android 7+ y con las políticas modernas de Android.
- Aplicar protección selectiva según sensibilidad y presupuesto de rendimiento.
- Diversificar cada build para evitar firmas y bypasses reutilizables.
- Proteger DEX, strings, constantes, recursos seleccionados y bibliotecas nativas.
- Detectar reempaquetado, re-firma, modificación de código e instrumentación runtime.
- Incorporar un motor RASP basado en señales y riesgo, no en una única detección.
- Ofrecer virtualización de métodos críticos mediante una VM por compilación.
- Permitir attestation y políticas remotas para aplicaciones con backend.
- Generar reportes, mapas privados y artefactos de retrace para mantener observabilidad.

## Principios de seguridad

1. Defense in depth: ninguna capa se considera suficiente por sí sola.
2. Per-build diversity: el mismo input debe producir protecciones estructuralmente diferentes.
3. Selective hardening: la máxima protección se concentra en lógica crítica.
4. Fail safe: una incompatibilidad no debe producir una falsa sensación de seguridad.
5. Measured security: cada release se valida con un laboratorio adversarial automatizado.
6. No secret-in-APK fallacy: secretos de alto valor no se consideran seguros solo por cifrarlos dentro del APK.
7. Runtime evidence: múltiples señales se correlacionan antes de aplicar una respuesta.
8. Update resilience: cambios internos del protector no deben romper el contrato público del Gradle Plugin ni la configuración.

## Componentes

| Componente | Responsabilidad |
|---|---|
| shield-core | Pipeline principal, modelo de proyecto protegido y orquestación |
| shield-dex | Parser/IR DEX, CFG/SSA y pases de transformación |
| shield-crypto | Primitivas, derivación de claves y protección de constantes |
| shield-integrity | Grafo de integridad, firma, certificado y verificaciones de contenido |
| shield-rasp | Señales runtime, scoring y políticas de respuesta |
| shield-native | Runtime nativo y hardening JNI |
| shield-vm | Virtualización selectiva de métodos críticos |
| shield-diversify | Semillas, mutaciones y variación por compilación |
| shield-gradle-plugin | Integración con Android Gradle Plugin |
| shield-cli | CLI multiplataforma |
| shield-studio | Interfaz de escritorio opcional |
| shield-lab | Pruebas adversariales y regresión de seguridad |

## Arquitectura resumida

    Android project / APK / AAB / AAR
                    |
                    v
          Input normalization
                    |
                    v
              DEX analysis
                    |
        +-----------+-----------+
        |           |           |
        v           v           v
    Obfuscation   Crypto    VM selection
        |           |           |
        +-----------+-----------+
                    |
                    v
          Resource protection
                    |
                    v
       Native runtime injection
                    |
                    v
      Integrity graph generation
                    |
                    v
       RASP policy embedding
                    |
                    v
           Package rebuild
                    |
                    v
      Validate -> Align -> Sign
                    |
                    v
           Protected artifact
                    |
                    v
        Security build report

## Stack propuesto

- Rust: motor principal, parser/IR, CLI, crypto orchestration y componentes nativos donde sea apropiado.
- Kotlin: Gradle Plugin, SDK Android y APIs de integración.
- Rust/C++ JNI: runtime nativo para comprobaciones de integridad y capas de alto coste.
- Compose Multiplatform: Shield Studio cuando se implemente la UI.
- Android Build Tools: zipalign/apksigner para firma APK en las primeras versiones.
- bundletool y herramientas oficiales: validación de AAB y APK splits.
- Cargo fuzz/libFuzzer y property tests: fuzzing de parsers y transformaciones.
- GitHub Actions: CI, matrices Android, fuzz smoke tests y publicación de artefactos.

## Modos de protección

### Standard
Ofuscación segura, cifrado de strings seleccionadas, integridad de certificado/contenido, RASP básico y diversificación.

### Hardened
Añade transformaciones de control de flujo, cifrado ampliado, runtime nativo, grafo de integridad distribuido y políticas RASP avanzadas.

### Maximum
Añade virtualización selectiva, diversificación agresiva, attestation opcional y controles de integridad redundantes. Solo debe aplicarse a superficies críticas debido al coste de tamaño, arranque y CPU.

## Motor RASP

Nexora Shield no dependerá de una comprobación única. El runtime combinará señales como:

- debugger e instrumentation;
- procesos/bibliotecas inyectadas y hooking;
- frameworks de modificación;
- entorno root/modificado;
- emuladores y entornos de análisis;
- firma/certificado inesperados;
- cambios de DEX, recursos o bibliotecas;
- inconsistencias en memoria;
- attestation remota opcional.

Las señales alimentan un risk score configurable. Las respuestas disponibles serán: log local, telemetría opt-in, bloquear solo una operación sensible, solicitar reautenticación/attestation o finalizar de forma controlada. El bloqueo ciego de dispositivos root no será la política predeterminada.

## Virtualización selectiva

Los métodos marcados como de alto valor podrán transformarse a un bytecode interno interpretado por una VM de Nexora Shield. Cada build podrá cambiar:

- mapa de opcodes;
- codificación de operandos;
- layout de tablas;
- claves derivadas;
- orden de handlers;
- seeds y constantes.

La virtualización nunca será global por defecto. Se medirá el impacto y se impondrán presupuestos de rendimiento.

## Diversificación por compilación

Cada protección genera un Build Protection Manifest privado con:

- build id;
- semilla criptográfica;
- versión del pipeline;
- transformaciones aplicadas;
- mapping/retrace;
- políticas RASP;
- hashes esperados;
- información necesaria para reproducibilidad controlada.

La semilla no se publicará con el APK. CI podrá custodiarla como artefacto privado o secret material.

## Integración prevista

CLI:

    nexora-shield protect app.apk --config nexora-shield.yml --output app-protected.apk
    nexora-shield inspect app-protected.apk
    nexora-shield verify app-protected.apk
    nexora-shield retrace --mapping mapping.nshield crash.txt

Gradle:

    plugins {
        id("dev.nexora.shield")
    }

    nexoraShield {
        profile.set("hardened")
        configFile.set(layout.projectDirectory.file("nexora-shield.yml"))
    }

## Documentación

- docs/ARCHITECTURE.md — arquitectura y límites entre módulos.
- docs/THREAT-MODEL.md — activos, atacantes, escenarios y no-objetivos.
- docs/SECURITY-DESIGN.md — capas de protección y decisiones de diseño.
- docs/CONFIGURATION.md — modelo de configuración.
- docs/TESTING.md — estrategia de pruebas funcionales, rendimiento y seguridad.
- docs/ROADMAP.md — fases de implementación y criterios de salida.
- SECURITY.md — política de reporte de vulnerabilidades.

## Roadmap resumido

0. Foundation y especificación.
A. Core packaging y pipeline reproducible.
B. DEX IR y ofuscación segura.
C. Cifrado de strings/constantes/recursos.
D. Integrity/anti-tamper.
E. RASP y motor de riesgo.
F. Native Shield.
G. VM Shield.
H. Diversificación polimórfica.
I. Attestation/políticas remotas opcionales.
J. Gradle Plugin y CI/CD.
K. AAB/AAR/splits.
L. Shield Studio.
M. Security Lab, fuzzing y red-team regression.
N. Production hardening y 1.0.

## Criterio de éxito

Nexora Shield no se considerará exitoso porque una app de inspección muestre "Protección detectada". El criterio real será que:

- la aplicación protegida continúe funcionando;
- modificaciones y re-firmado sean detectados;
- strings y lógica crítica no aparezcan de forma trivial;
- bypasses de una compilación no se trasladen automáticamente a otra;
- el overhead permanezca dentro de presupuestos definidos;
- el laboratorio de regresión adversarial no encuentre degradaciones conocidas;
- los resultados sean repetibles cuando se conserve la semilla privada.

## Alcance ético

Nexora Shield está diseñado para proteger software propio o software para el que se cuenta con autorización. El proyecto no debe incorporar funciones de persistencia maliciosa, evasión de controles del sistema, explotación de dispositivos ni comportamiento que oculte malware.

## License

Licencia pendiente de decisión del propietario del repositorio.
