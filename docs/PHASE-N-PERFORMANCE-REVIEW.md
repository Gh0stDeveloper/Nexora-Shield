# Nexora Shield 1.0 RC — performance review

> **Post-Phase-N audit clarification:** these measurements are valid for the production `protect` path that existed during Phase N. The later Phase O audit found that this path did not yet orchestrate the complete B–I protection stack into the final artifact. O.11 must therefore repeat performance qualification after the O.1–O.5 production integration is complete.

## RC scope

RC qualification validates deterministic budget logic and protection-overhead accounting through Phase M.

The RC review covers:

- protected artifact growth;
- protection operation overhead;
- VM method cost estimation;
- build-time budget evaluation.

## Stable performance evidence

N.10 now has reproducible Android execution evidence from **Phase N #54** (run `37686651703`) on the standardized Android ATD environment:

- Android 15 / API 35;
- x86_64;
- model: `Android ATD built for x86_64`;
- 5 warmups per variant;
- 20 measured runs per variant;
- identical signing identity for baseline and protected APKs.

| Metric | Baseline | Protected |
| --- | ---: | ---: |
| Startup p50 | 136 ms | 130 ms |
| Startup p95 | 147 ms | 145 ms |
| Median total PSS | 17,851 KB | 17,845 KB |
| Signed APK size | 648,445 bytes | 648,445 bytes |

The benchmark result is `passed: true` under the configured budgets.

### Artifact identity

The signed APKs are **not byte-identical**:

- baseline SHA-256: `84836a351f475677d0d7b9b28fc43695fa27d4413b58fc56e5ee0cf1ccc9c24a`;
- protected SHA-256: `0d0faf5aea3b624fb85bda9b2c499fc0c0f6ce00cb3daf40f2be4b38c897c840`.

Before signing, CI also verifies that the selected protected APK exactly matches the authoritative Nexora Shield public report:

- profile: `hardened`;
- input SHA-256: `1d90a04ccf68daaea6ee4c5842f229cdfb82d1582e45f193d101c3e2e3e1fae1`;
- output SHA-256: `2af9e8cbb8d7772544f3bb13dd183a854a939a681dadf64f77fa791647e5e26a`;
- input size: 639,030 bytes;
- output size: 639,028 bytes.

This prevents N.10 from passing by accidentally benchmarking the unprotected AGP output twice.

## Evidence retention

Workflow artifact `phase-n-android-performance`:

- artifact id: `11512011963`;
- digest: `sha256:ffe41bb1570dfab2f70ba6b1f138c68c377aaf7177293db6f4669fd9bd56ccf2`;
- contains baseline/protected sample sets, comparison JSON, public report and emulator diagnostics.

## Measurement discipline

The gate uses the Phase M comparative methodology: same execution environment, same signing identity, warmups, repeated measured runs and retained raw samples.

Physical-device profiling can still be added as supplementary field telemetry later, but it is not substituted for or mixed with this reproducible CI release gate.
