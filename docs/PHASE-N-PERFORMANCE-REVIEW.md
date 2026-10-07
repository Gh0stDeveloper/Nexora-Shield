# Nexora Shield 1.0 RC — performance review

## RC scope

RC qualification validates deterministic budget logic and protection-overhead accounting through Phase M.

The RC review covers:

- protected artifact growth;
- protection operation overhead;
- VM method cost estimation;
- build-time budget evaluation.

## Stable-only device evidence

CI runner timings are not presented as Android runtime performance.

Before stable `v1.0.0`, representative Android measurements must be recorded for:

- startup p50/p95;
- memory delta;
- final protected APK/AAB size delta.

The machine-readable state is `../release/performance-review.json`. While `stableDeviceMeasurementsComplete` is false, the stable release workflow must reject `v1.0.0`.

## Measurement discipline

Use the Phase M comparative methodology: same device, same OS image, same toolchain, warm-ups, repeated measured runs and retained raw samples.
