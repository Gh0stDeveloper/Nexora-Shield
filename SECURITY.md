# Security Policy

## Supported versions

Durante pre-1.0 solo la rama principal y la release más reciente reciben correcciones de seguridad.

## Reporting

No publiques un exploit funcional de una vulnerabilidad no corregida como issue público.

Incluye en el reporte:

- versión de Nexora Shield;
- plataforma;
- tipo de artefacto;
- configuración mínima para reproducir;
- impacto;
- pasos de reproducción;
- logs sin secretos;
- prueba de concepto mínima si es necesaria.

Nunca incluyas:

- keystores;
- contraseñas;
- production tokens;
- private build manifests;
- seeds;
- datos personales.

## Scope

Interesan especialmente:

- bypass genérico de integrity;
- bypass genérico de RASP;
- recuperación de material privado de build;
- corrupción del transformer;
- ejecución de código durante análisis de un input malicioso;
- path traversal/ZIP attacks;
- firma incorrecta;
- fuga de secretos de CI;
- bypass reusable entre builds;
- VM verifier bugs;
- cryptographic misuse.

## Response priorities

Critical:
- compromiso de signing/build secrets;
- ejecución de código en la máquina que protege el APK;
- bypass genérico multi-build.

High:
- neutralización reproducible de una capa principal;
- fuga significativa de mappings;
- integridad incorrecta.

Medium/Low:
- fingerprinting;
- bypass limitado a una configuración;
- falsos positivos;
- degradaciones sin compromiso completo.

## Safe research

La investigación debe realizarse sobre aplicaciones propias, samples de Nexora Shield o software para el que exista autorización.

## Security promises

El proyecto no afirma que una app sea imposible de romper. Las garantías publicadas deben estar respaldadas por tests y un threat model explícito.
