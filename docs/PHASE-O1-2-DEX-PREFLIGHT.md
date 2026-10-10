# Phase O.1.2 — Multidex, compatibility and selector preflight

Status: **IMPLEMENTED ON FEATURE BRANCH — CI VERIFICATION REQUIRED**.

## Scope and security boundary

- The production planner verifies input SHA-256 before and after read-only inspection.
- Canonical `classes.dex`, `classes2.dex`, etc. are checked with bounded STORE
  and DEFLATE decoding: 64 MiB per DEX, 256 MiB aggregate.
- `MultiDexSet::parse` is the common authority for contiguous DEX numbering
  and duplicate class ownership across all DEX units, not only in the CLI.
- Only defined class/method/field symbols are eligible. Reference-only IDs
  cannot be selected as hypothetical transformation targets.
- Selector globs `*` and `?` use bounded-memory byte matching; each pattern
  is limited to 256 bytes, and a policy to 128 total include/exclude rules.
- Rules resolve globally across the APK's DEX inventory. Every explicit
  include or exclude must match a real symbol, and an effective empty set
  fails closed. Exclusions are applied after all inclusions.
- Each DEX reports its version, selected symbols, JNI/native methods,
  reflection indicators and protected-name counts. Cross-DEX reflection
  detection is a conservative **heuristic**, not a semantic safety proof.
- O.1.2 **does not** execute the complete protected-APK pipeline; runtime
  integrations and production-stage evidence remain pending. `protect`
  continues to fail closed until required integrations exist.

## Read-only usage

```sh
nexora-shield protect input.apk --output intended.apk \
  --unsigned --no-align --plan-only \
  --method 'Lcom/example/Auth;#verify*' \
  --class 'Lcom/example/Billing*;' \
  --exclude-class 'Lcom/example/Generated*;'
```

`--class`, `--method` and `--field` select **only that symbol kind**;
method/field rules use `<class-descriptor>#<member-glob>`. The corresponding
`--exclude-class`, `--exclude-method` and `--exclude-field` rules subtract
matching symbols. Without include rules, all defined classes and members
are selected before exclusions. A rule must match at least one symbol across
all DEX units. `package-apk` rejects these production-only options.

YAML schema-v1 selector binding remains part of O.5. These CLI arguments
do not imply that declarative YAML is executable yet.

## Tests and remaining gate

Phase O E2E builds synthetic non-installable multidex APKs and asserts
deterministic selector outcomes, invalid rule rejection, no artifact writes,
and failure of incomplete production execution. The DEX crate tests class
duplication and numbering violations. This is not O.2 Android install/
launch or proof of final protected bytes, and must not be marked as such.

Release status stays NO-GO until the parent Phase O audits complete.
