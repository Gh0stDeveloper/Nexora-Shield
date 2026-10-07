# Phase G — VM Shield checklist

## G.1 Eligibility analyzer
- [x] Method eligibility report
- [x] Register/instruction budgets
- [x] Call/field/exception policy
- [x] Unsupported-opcode rejection
- [x] DEX IR validation

## G.2 VM IR
- [x] Typed registers
- [x] Parameter mapping
- [x] VM instructions
- [x] Exception handlers
- [x] Method validation

## G.3 Opcode model
- [x] Semantic opcode model
- [x] Forward/reverse mapping
- [x] Full operand-bearing opcode stream
- [x] Stream decoder
- [x] Allocation fingerprint

## G.4 Lowering
- [x] DEX-to-VM lowerer
- [x] Move/constants
- [x] Integer arithmetic
- [x] Branches/goto
- [x] Calls + move-result
- [x] Instance/static fields
- [x] Throw/return
- [x] DEX exception-table lowering
- [x] Unsupported instruction rejection

## G.5 Interpreter
- [x] Register execution
- [x] 32-bit wrapping arithmetic
- [x] Branch execution
- [x] Return semantics
- [x] Allocated bytecode execution
- [x] Step limit
- [x] Method validation before execution

## G.6 Exception semantics
- [x] Typed exception model
- [x] Arithmetic exception
- [x] Explicit throw
- [x] Host exceptions
- [x] Typed handlers
- [x] Catch-all handlers
- [x] Exception-register transfer
- [x] Host exception construction
- [x] Host subtype/assignability matching

## G.7 Calls/fields
- [x] VmHost boundary
- [x] Instance/static reads
- [x] Instance/static writes
- [x] Method calls
- [x] Host exception propagation

## G.8 Constant pools
- [x] Int/string/type constants
- [x] Deduplication
- [x] Bounds checks
- [x] Deterministic pool digest

## G.9 Per-build opcode allocation
- [x] Build-id input
- [x] Private-seed input
- [x] Deterministic same-build mapping
- [x] Different-build mapping
- [x] Opcode-map fingerprint

## G.10 Metadata sealing
- [x] HMAC-SHA-256
- [x] Versioned metadata
- [x] Pool digest binding
- [x] Opcode fingerprint binding
- [x] Encoded bytecode digest binding
- [x] Parameter/handler control metadata binding
- [x] Sealed execution path
- [x] Seal-key debug redaction
- [x] Wrong-allocation rejection path
- [x] Bytecode tamper rejection
- [x] Wrong-key rejection

## G.11 Performance estimator
- [x] Static instruction weighting
- [x] Host-boundary weighting
- [x] Relative-cost estimate

## G.12 Differential tests
- [x] Integer boundaries
- [x] 4096 generated add cases
- [x] Branch differential cases
- [x] Exception semantics tests
- [ ] Final CI differential gate

## G.13 Selective annotations/config
- [x] Config selectors
- [x] Annotation method-set input
- [x] Config-only
- [x] Annotation-only
- [x] OR mode
- [x] AND mode
- [x] Strict JSON schema

## G.14 VM security benchmark
- [x] Multi-build opcode diversity report
- [x] Unique-map metric
- [x] Transfer-ratio metric
- [x] 32-build regression benchmark
- [ ] Final CI security gate

## Closure state

Phase G implementation is **IN PROGRESS**. G.1–G.14 code is present, but the phase is not closed until the dedicated VM, differential, security, MSRV and full workspace regression gates are green on the final head.
