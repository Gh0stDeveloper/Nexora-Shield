# Phase O.1.3 — Private encrypted retrace maps

Status: **INTEGRATED IN DIAGNOSTIC STAGING — EXACT-HEAD CI REQUIRED**.

## Scope and security model

DEX fixed-layout transformations keep a private list of original and obfuscated
strings per DEX string index, with symbol-usage labels. Because these mappings
disclose names that would otherwise be hidden, they **must never appear in the
APK, release assets, public logs, public build reports or version control**.

- The map is serialized only into an in-memory buffer, immediately sealed
  using the existing authenticated XChaCha20-Poly1305 protected container.
- Key material is supplied at runtime; the 32-byte root secret is **not
  included in the APK**. The caller provides a unique application/build
  identity through `KeySchedule`. Retrace sidecars use a purpose-specific
  logical ID bound to the **actual verified staged APK SHA-256**.
- Opening a map requires the correct private key, application/build identity
  and expected APK hash. Bad ciphertext, a wrong build, and changed APK
  identities fail authentication.
- The sidecar is created **only at a new path** using Unix exclusive creation
  and permission mode `0600`. Pre-existing destinations and symlink leaves are
  never overwritten. Outside Unix the protected-staging API refuses output
  until equivalent secure file semantics are implemented.
- If map encryption or writing fails after the APK was staged, the new APK is
  removed rather than returned as a successful build without its private map.
  Unexpected disk crashes can still require manual cleanup; the workflow
  makes no production-transaction claim.
- Retrace records are subject to format, count, schema, DEX identity and
  payload-size validation. Library debug formatting redacts original names.
- This feature **does not publish a general plaintext mapping file**. The
  `open_retrace_map` API returns private records only to an explicitly
  authorized caller for local debugging. Ambiguous reverse lookups return all
  candidates; they must not silently guess among overloads.

## Opt-in internal diagnostic usage

Create a 32-byte key file outside the repository with owner-only permissions.
Do **not** put the root secret into CLI arguments or the APK.

```bash
umask 077
python3 -c 'import os; fd=os.open("/secure/retrace.key",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.write(fd,os.urandom(32)); os.close(fd)'
chmod 600 /secure/retrace.key

cargo run --locked -p nexora-shield-core --example stage_dex -- \
  input.apk staged-unsigned.apk \
  --retrace-map /secure/staged-unsigned.retrace.nsr \
  --retrace-key-file /secure/retrace.key \
  --application-id com.example.app --build-id build-20261008-1
```

To authenticate and inspect the encrypted map without disclosing original
names, run:

```bash
cargo run --locked -p nexora-shield-core --example retrace_inspect -- \
  staged-unsigned.apk /secure/staged-unsigned.retrace.nsr \
  /secure/retrace.key com.example.app build-20261008-1
```

For a **deliberate local lookup only**, append
`--lookup classes.dex <obfuscated-name>`. This prints matching original
names to standard output; do not run that form in shared CI logs or release
pipelines. The command verifies the SHA-256 of the actual staged APK and
rejects a mismatched build identity, key, map or modified ciphertext.

The staged APK remains diagnostic and unsigned. The sidecar is a separate
encrypted local artifact, bound to the verified output hash. Use an external
encrypted vault with strict ACLs, retention controls and backups for production
custody of root secrets and retrace archives.

## Test coverage

- Crypto roundtrip and protected-input validation.
- Tamper detection, wrong root secret, wrong build identity, wrong APK hash.
- Duplicate/empty records, redacted debug formatting, ambiguous candidate
  lookups and ciphertext plaintext-exposure checks.
- Unix mode `0600`, exclusive no-overwrite and symlink protections.
- Phase O CI generates two real synthetic DEX units, stages and verifies an
  APK plus encrypted retrace sidecar, checks the sidecar is **not** in the APK
  and refuses reuse of the map path.
- No production Android ART equivalence, native/reflection rewrites, complete
  stack-frame deobfuscation (owner/signature disambiguation), server key escrow
  or operational recovery SLA is certified here.

## Release boundary

This step does **not** lift the Phase O release freeze. Phase O.1.3 remains
OPEN until all required compatibility and production-integrated verification
work is finished. Stable `v1.0.0` stays **NO-GO**.
