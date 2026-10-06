# Build Artifacts

## 1. Objetivo

Separar estrictamente artefactos publicables de material que ayuda a reconstruir o analizar la protección.

## 2. Públicos

Puede publicarse:

- APK/AAB protegido;
- checksum;
- SBOM;
- versión de Nexora Shield;
- public security report;
- release notes;
- provenance sin secretos.

## 3. Privados

No deben publicarse:

- symbol mapping;
- full transform manifest;
- VM opcode mapping;
- build seed;
- derived-key material;
- detailed integrity topology;
- raw RASP calibration data;
- private retrace package.

## 4. Private Build Manifest

Formato lógico:

    header
      schema
      shield_version
      build_id
      input_hash

    diversity
      seed_reference
      variants

    mappings
      symbols
      vm
      transforms

    integrity
      graph_metadata

    retrace
      metadata

Debe cifrarse cuando se almacene fuera de un entorno confiable.

## 5. Retention

Recomendación:

- stable releases: conservar mapping/retrace mientras se soporte la versión;
- beta: ventana definida;
- nightly: retención corta;
- seeds: acceso más restrictivo que reportes.

## 6. CI

Los jobs públicos nunca imprimirán material privado. Se crearán dos canales:

    public artifacts
    restricted artifacts

## 7. Reproducir un build

Requiere:

- input commit;
- dependency locks;
- Shield version;
- AGP/build tools versions;
- config;
- seed privada;
- signing setup apropiado.

## 8. Desastre

Si se pierde mapping:

- la app sigue funcionando;
- crash retrace puede degradarse;
- no se debe poder recuperar el mapping completo desde el APK.

Si se filtra seed/mapping:

- tratar como incidente;
- rotar build;
- invalidar build remoto si existe remote policy;
- generar nueva seed;
- analizar impacto.
