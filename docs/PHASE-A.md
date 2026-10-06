# Phase A — Core Packaging

## Status

Implementation branch: `feat/phase-a-core-packaging`.

Phase A establishes the first executable Nexora Shield protection pipeline. It intentionally does **not** transform DEX instructions yet; that begins in Phase B. The Phase A contract is that Nexora Shield can accept a standard APK, inspect it safely, normalize its ZIP structure, remove stale v1 signing metadata, preserve packaged payload identity, optionally align it using the official Android `zipalign`, sign it using the official `apksigner`, verify the result and publish it transactionally.

## A.1 — Rust workspace

Implemented modules:

- `nexora-shield-package`
  - standard ZIP32/APK parsing;
  - deterministic normalization;
  - manifest metadata inspection;
  - multi-DEX discovery;
  - SHA-256;
  - Android Build Tools discovery;
  - zipalign/apksigner integration.
- `nexora-shield-core`
  - immutable BuildPlan;
  - transaction workspace;
  - pipeline state machine;
  - public/private reports.
- `nexora-shield`
  - CLI.

The package boundary is dependency-free in Phase A to reduce the trusted parser surface.

## A.2 — CLI skeleton

Implemented stable commands:

~~~text
nexora-shield protect
nexora-shield inspect
nexora-shield verify
nexora-shield profiles
~~~

The CLI fails closed. A `protect` invocation without signing configuration must explicitly opt into `--unsigned`.

## A.3 — ZIP/APK normalizer

The normalizer:

- parses the End of Central Directory;
- validates single-disk standard ZIP32;
- rejects ZIP64 explicitly in Phase A;
- validates central/local header agreement;
- rejects duplicate names;
- rejects encrypted entries;
- rejects unsafe entry names;
- supports STORE (0) and DEFLATE (8);
- copies compressed payloads byte-for-byte;
- orders entries deterministically by UTF-8 name;
- removes archive comments;
- normalizes DOS timestamps;
- removes timestamp and stale zipalign padding extra fields;
- strips stale JAR/v1 signing metadata from `META-INF`;
- rebuilds local and central records with new offsets;
- rejects offsets/sizes that would exceed ZIP32.

The normalizer never decompresses/recompresses application payloads in Phase A. That reduces semantic drift and lets content equivalence be checked through the ZIP metadata and CRC identities.

### Stripped stale signatures

The following pre-existing v1/JAR metadata is removed before a new signature is generated:

- `META-INF/MANIFEST.MF`
- `META-INF/*.SF`
- `META-INF/*.RSA`
- `META-INF/*.DSA`
- `META-INF/*.EC`
- `META-INF/SIG-*`

APK Signing Block v2/v3 signatures are not ZIP entries and naturally disappear when the archive is rebuilt.

## A.4 — Manifest inspection

Phase A requires `AndroidManifest.xml` to exist.

Inspection records:

- compression method;
- compressed/uncompressed size;
- CRC32;
- SHA-256 when the manifest is stored and bounded;
- detected format:
  - Android binary XML header;
  - text XML;
  - unknown stored;
  - compressed/uninspected.

Full Android binary XML semantic decoding is intentionally not implemented in Phase A because it is not required to establish packaging correctness.

## A.5 — Multi-DEX discovery

The inspector recognizes only root-level canonical names:

~~~text
classes.dex
classes2.dex
classes3.dex
...
~~~

Invalid forms such as `classes01.dex` or nested paths do not count.

Verification rejects gaps such as:

~~~text
classes.dex
classes3.dex
~~~

because a discontinuous sequence is suspicious and not a canonical multidex layout.

## A.6 — BuildPlan

Before modification, the core freezes an immutable `BuildPlan` containing:

- build ID;
- configuration schema;
- protection profile;
- input/output paths;
- input SHA-256;
- creation timestamp;
- alignment/signing intent;
- expected DEX count.

Once execution begins, the plan is not silently mutated.

## A.7 — Transactional pipeline

The lifecycle is:

~~~text
PLANNED
  -> NORMALIZED
  -> CONTENT_VERIFIED
  -> ALIGNED (optional)
  -> SIGNED (optional)
  -> PACKAGE_VERIFIED
  -> PUBLISHED
~~~

Intermediate APKs live in a transaction directory adjacent to the requested output. The final artifact is only renamed into place after verification.

With `--force`, an existing output is first moved to a backup. If publishing the replacement fails, the backup is restored.

Transaction directories are cleaned automatically.

## A.8 — Public/private reports

### Public report

Contains non-secret CI-safe information:

- build ID;
- schema/profile;
- input/output SHA-256;
- sizes;
- output entry count;
- DEX count;
- manifest format;
- alignment/signing result;
- number of stripped stale signatures;
- completed stages.

### Private report

Contains operational build information intended for restricted storage:

- exact input/output paths;
- creation timestamp;
- DEX filenames;
- stripped signature filenames;
- completed stages.

No signing password is ever serialized.

Future phases extend the private report with mappings and protection metadata.

## A.9 — apksigner / zipalign

Nexora Shield uses official Android Build Tools rather than implementing its own APK signer.

Discovery order:

1. explicit CLI path;
2. newest numeric build-tools directory under `ANDROID_SDK_ROOT`;
3. `ANDROID_HOME`.

Alignment:

~~~text
zipalign -P 16 -f 4 input.apk output.apk
zipalign -c -P 16 4 output.apk
~~~

This selects 16 KiB shared-object page alignment support while retaining 4-byte ZIP alignment.

Signing:

- V1 enabled;
- V2 enabled;
- V3 enabled;
- V4 disabled in Phase A because its `.idsig` is a separate deployment artifact;
- explicit minimum SDK;
- keystore/key passwords are referenced by environment-variable name, never placed directly in the Nexora Shield config/report.

After signing, Nexora Shield calls `apksigner verify --verbose --print-certs`.

## A.10 — protect / inspect / verify

### Protect

~~~bash
nexora-shield protect app.apk \
  --output app-protected.apk \
  --profile hardened \
  --keystore release.p12 \
  --alias release \
  --ks-pass-env ANDROID_KS_PASSWORD \
  --key-pass-env ANDROID_KEY_PASSWORD \
  --public-report build/shield-report.json \
  --private-report private/build-manifest.json
~~~

Unsigned output must be explicit:

~~~bash
nexora-shield protect app.apk \
  --output normalized.apk \
  --unsigned \
  --no-align
~~~

### Inspect

~~~bash
nexora-shield inspect app.apk
nexora-shield inspect app.apk --json
~~~

### Verify

~~~bash
nexora-shield verify app.apk
nexora-shield verify app.apk --signature --min-sdk 24
~~~

## Exit criteria

Phase A is CLOSED only when all of the following pass in GitHub Actions:

1. rustfmt;
2. Clippy with warnings denied;
3. workspace tests;
4. rustdoc;
5. RustSec audit;
6. package normalizer integration tests;
7. transactional pipeline integration tests;
8. a real end-to-end CI fixture:
   - create APK;
   - normalize;
   - zipalign;
   - V1/V2/V3 sign;
   - inspect;
   - verify with apksigner;
   - validate public/private JSON reports.

## Explicit Phase A limitations

These limitations are deliberate and visible rather than silently unsupported:

- standard ZIP32 only;
- no ZIP64 APK normalization;
- no AAB/AAR processing yet;
- no DEX instruction parsing/transformation yet;
- no full Android binary XML decode yet;
- only STORE and DEFLATE entry methods;
- signing relies on official Android Build Tools.

The next phase, Phase B, begins the DEX parser/writer, verifier, CFG/IR and structural obfuscation engine.
