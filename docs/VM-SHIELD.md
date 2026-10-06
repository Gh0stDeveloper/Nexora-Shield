# VM Shield

## 1. Propósito

VM Shield es la capa de protección para métodos de máximo valor. Convierte un subconjunto del programa a una representación ejecutada por un runtime propio. No busca virtualizar una aplicación completa.

## 2. Razón

La ofuscación convencional conserva gran parte de la semántica DEX. La virtualización introduce una representación adicional y permite que cada build cambie la codificación interna.

## 3. Selección

Elegibles inicialmente:

- lógica pura;
- validadores;
- pequeñas reglas de negocio;
- funciones criptográficas de glue, no primitivas inventadas;
- checks de licencia;
- operaciones sensibles de tamaño controlado.

Evitar inicialmente:

- métodos UI;
- Compose runtime;
- loops muy calientes;
- reflection compleja;
- native methods;
- synchronized;
- métodos gigantes;
- bytecode raro no soportado.

## 4. Pipeline

    Method DEX IR
        |
        v
    Eligibility
        |
        v
    Semantic normalization
        |
        v
    VM IR
        |
        v
    Per-build allocation
        |
        +--> opcodes
        +--> registers
        +--> constant pool layout
        +--> handler order
        |
        v
    Seal metadata
        |
        v
    Replace original body with bridge
        |
        v
    Runtime interpreter

## 5. Diseño del VM IR

Debe ser:

- tipado suficientemente para validar;
- pequeño;
- independiente del opcode numbering;
- capaz de expresar branches, locals, constants, field access y calls permitidas;
- versionado.

La asignación final de opcodes ocurre después del IR.

## 6. Diversidad

Build A y Build B deben poder asignar distintos números y layouts al mismo IR. La diversidad no debe cambiar semántica.

## 7. Runtime

Requisitos:

- modular;
- sin estado global innecesario;
- validar metadata antes de ejecutar;
- límites de memoria;
- handling controlado de errores;
- telemetría opcional;
- integración con integrity graph.

## 8. Metadata

Metadata VM se cifra/autentica y queda ligada a:

- build id;
- package;
- versión de runtime;
- integrity node.

No contiene la seed maestra.

## 9. Performance

Para cada método candidato se estima:

    cost_score = frequency * instruction_count * vm_penalty

El planner puede rechazar virtualización si excede presupuesto.

## 10. Testing

Differential execution:

- original vs virtualized;
- seeds múltiples;
- values boundary;
- exceptions;
- null;
- arrays;
- object fields;
- calls.

## 11. Seguridad

VM Shield no se vende como "irrompible". Un analista puede estudiar el interpreter. La defensa se basa en:

- selección pequeña;
- mapas per-build;
- metadata protegida;
- integración con integrity;
- runtime diversity futura;
- reducción de reutilización entre builds.

## 12. Versiones futuras

- múltiples dispatch backends;
- superinstructions;
- native interpreter variant;
- mixed interpreters por método;
- profile-guided selection;
- adaptive VM budget.

Cada nueva variante debe pasar el mismo verifier y suite diferencial.
