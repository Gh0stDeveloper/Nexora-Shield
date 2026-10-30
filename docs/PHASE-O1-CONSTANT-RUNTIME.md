# O.1 encrypted constant runtime increment

Status: **partial Android integration; O.1 OPEN; stable v1.0.0 NO-GO**.

The starting branch HEAD was verified through the Ghost Developer connection as
`2c30738de23c152cdf7759744a1264d190dfb770` before these edits. The preceding
[signed guard/RASP increment](PHASE-O1-GUARD-RUNTIME.md) remains in effect.

## Executed data path

Explicitly selected static literal getters returning `boolean`, `int`, `long`,
`float` or `double` now use the existing constant protection engine. The planner
accepts exactly one matching-width DEX constant instruction followed by a return
from the same register, without handlers, arguments, annotations or synchronization.
It rejects unsupported types, invalid boolean values and NaNs; it does not silently
substitute VM execution for an incompatible selected constant getter.

The original body is replaced by a typed call to the generated helper. JNI checks
the installed guard and current RASP policy, authenticates and decrypts the
build-derived constant container, creates the matching Java wrapper, and the stub
unboxes it to the original primitive return type. This preserves the verifier's
type contract and the raw bits of negative zero. Both Android ABIs export and
verify the new entry point. The helper fingerprint binds the ciphertext inventory.

Plaintext encoding/decryption buffers and primitive `ConstantValue` storage now
use zeroization. Returned Java values necessarily remain observable to the app;
this is not a claim of hardware secrecy or immunity to dynamic extraction.

## Evidence and limits

The retained tests cover DEX const sign extension and all narrow/wide encodings,
AEAD corruption, wrong entry types, duplicate slots, integer boundaries and float
bit preservation. The real JVM harness calls the compiled JNI entry point for all
five primitive types and rejects a string slot used as a constant. The Android
fixture executes all five original getters before and after transformation,
compares output digests, and checks raw float/double bits without retaining a
second plaintext copy of the selected integer literals in DEX.

The signed-fixture qualification checks the selected 32/64-bit literal probes are
present in the baseline DEX and absent after rewriting, alongside the existing
string/root/private-key exposure checks. This is a fixture-specific extraction
probe, not an assertion that every small constant can disappear from an APK.
Reports include the actual protected-constant count and final signed APK hashes.
The same 22-case guard/RASP Android matrix must pass on this exact increment;
a previous commit's device result is not evidence for the changed JNI ABI.

Local checks: 235 all-feature workspace tests, real JVM positive/tamper execution,
Smali round-trip and both Android ABI builds. Signed APK/graph qualification,
strict Clippy, formatting, Rust 1.81 checks and release/documentation checks are
required before publication. Device execution is performed by the existing
non-skipping Phase O Android job; local KVM is unavailable.

General constant use-site rewriting, resource decryption/access rewriting,
broader Native/VM compatibility, delivered diversification and private
reproducibility, optional attestation, and the complete shared production
transaction for CLI/Gradle/Studio remain open. No stage is promoted to
`ProductionIntegrated`, and O.2 has not started.
