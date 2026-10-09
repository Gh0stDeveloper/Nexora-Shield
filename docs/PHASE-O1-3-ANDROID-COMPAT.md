# Phase O.1.3 — Android Manifest, resources, JNI and reflection gate

Status: **diagnostic fail-closed compatibility gate**. This is not an
Android resource relinker, binary XML parser or production APK protector.

## Purpose

A valid, executable DEX does not prove that Android can find its manifest
components, XML callback methods, reflection targets, JNI classes/methods,
serialized identifiers, or dynamically loaded entrypoints. The Phase O.1.3
staging executor now audits proposed DEX string rename reports against the
original APK's non-DEX contracts **before writing any output APK**.

If the contracts cannot be linked with high confidence, the operation fails.
This intentionally sacrifices some obfuscation opportunities rather than
producing an apparently valid but broken Android package.

## Enforced rules

| Surface | Diagnostic treatment |
| --- | --- |
| Text AndroidManifest.xml | Decode bounded UTF-8; reject renamed class descriptors, fully qualified dotted names, relative or quoted simple component names |
| Text layout/configuration/XML and JSON files | Scan supported bounded text entries for renamed class and member names, including Android `android:onClick` callbacks |
| Binary AndroidManifest.xml or compiled resource XML | Reject rename: an Android binary XML string-pool/attribute relinker is not yet certified |
| `resources.arsc` | Reject rename: compiled resource references are not yet verified |
| Packaged `lib/**/*.so` or native DEX methods | Reject rename: `JNI_OnLoad`, native registrations and external `FindClass`/`GetMethodID` contracts may depend on original names |
| Reflective API method IDs | Detect `Class.forName`, `Class.getDeclaredMethod`, `ClassLoader.loadClass`, MethodHandles lookup APIs and Proxy creation even when no literal reflection name exists; reject rename |
| No renamed strings / metadata-only change | Pass the external name-binding gate without claiming broader runtime compatibility |

The checks also bound the total bytes read from XML and text configuration
files and refuse unrecognized encoding/formats. Non-DEX ZIP payloads remain
byte-preserved by the existing staged APK reconstruction verifier.

## Compatibility limits

This diagnostic gate does not claim complete reflection or JNI call-graph
resolution. Dynamically generated names and references embedded in arbitrary
binary assets can evade textual scanning. Consequently, **a successful gate is
not Android ART runtime certification**. The next implementation must decode
and structurally relink compiled Android resources/binary XML, analyze native
registration tables, resolve reflection policies and confirm behavior through
instrumented install/start tests. A production build with unsafe or unresolved
contracts must remain blocked.

## Tests

- Unit-level checks for manifest relative, bare, fully qualified and DEX
  descriptor aliases; XML `onClick`, JSON embedded class names, and an
  unreferenced ordinary manifest.
- DEX-level tests identify reflection APIs from method IDs (including no
  `const-string`).
- Phase O CI constructs adversarial real DEX-bearing synthetic APK fixtures for
  manifest components, binary XML, callback XML, JSON resources, compiled
  resource tables and native ELF libraries. Each must fail **without producing
  a staged APK**. The prior no-reference text manifest fixture must continue
  to stage successfully.
- These fixtures remain intentionally non-installable; they are regression
  inputs, not physical Android evidence.

See [O.1.3 transforms](PHASE-O1-3-TRANSFORMS.md) and
[private retrace maps](PHASE-O1-3-RETRACE.md).

The parent O.1.3 and Phase O remain **OPEN**. Stable `v1.0.0` is **NO-GO**.
