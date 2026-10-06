# APK Packaging Invariants

## Purpose

This document defines what Phase A is allowed to change while rebuilding an APK.

## Payload identity

For every non-signature ZIP entry, normalization must preserve:

- filename;
- CRC32;
- uncompressed size;
- compression method;
- compressed payload bytes.

Phase A may change:

- ZIP entry order;
- local-header offsets;
- DOS timestamps;
- archive comment;
- non-semantic timestamp/alignment extra fields;
- stale signing metadata.

The payload itself is not decompressed or recompressed by the Nexora Shield normalizer.

## Why old signatures are removed

APK signatures authenticate archive structure/content. Any rebuild invalidates previous signatures.

Keeping stale `META-INF/*.SF` or certificate blocks would create an ambiguous artifact. Nexora Shield removes legacy signing metadata before the official signer is invoked.

V2/V3 signing blocks are located outside normal ZIP entries, between entry data and the central directory, so a fresh archive rebuild naturally omits them.

## Hostile-input handling

The APK parser treats its input as untrusted.

It rejects:

- duplicate entry names;
- path traversal;
- absolute names;
- Windows-style backslash names;
- encrypted entries;
- unsupported compression;
- inconsistent central/local filenames;
- truncated records;
- multi-disk ZIP;
- ZIP64 sentinels;
- size/offset arithmetic overflow.

No archive path is extracted to disk during inspection/normalization.

## ZIP64

ZIP64 is explicitly rejected in Phase A rather than partially handled. Silent truncation of 64-bit sizes/offsets is forbidden.

Support can be added later through a dedicated parser extension and test corpus.

## Data descriptors

Input entries may advertise a data descriptor through general-purpose flag bit 3.

The central directory provides authoritative sizes/CRC. During normalization, Nexora Shield writes exact values into the local header, clears bit 3 and omits the descriptor.

This produces a simpler canonical structure while preserving payload bytes.

## Extra fields

The normalizer keeps unknown extra fields but removes fields that conflict with deterministic metadata or must be regenerated:

- `0x5455` — extended timestamp;
- `0x000a` — NTFS timestamp;
- `0xd935` — Android zipalign padding.

Malformed extra-field TLVs cause the build to fail.

## Alignment

Alignment is not approximated by the internal ZIP writer. Official `zipalign` runs after normalization and before signing.

The pipeline verifies zipalign's own `-c` result.

## Signing order

Required order:

~~~text
normalize
  -> verify content identity
  -> zipalign
  -> verify alignment
  -> apksigner sign
  -> apksigner verify
  -> structural verify
  -> publish
~~~

Changing the APK after signing is prohibited because it invalidates the signature.

## Transaction boundary

The requested output path is not used as a working file.

All intermediate outputs are isolated in an adjacent transaction directory. This ensures an interrupted or failed run does not leave a half-protected artifact at the requested destination.

## Security note

Correct packaging is foundational but is not itself reverse-engineering protection. DEX/data/runtime hardening begins in later phases.
