//! Phase O.1.3 fail-closed APK-level binding gate.
//!
//! Until Android's compiled resource table/XML and native registration are
//! parsed and linked, the DEX-only fixed-layout writer MUST NOT publish
//! renamed symbols whose non-DEX ABI contracts cannot be rewritten.
use crate::{CoreError, Result};
use nexora_shield_dex::{CompatibilityAnalyzer, DexRewriteOutput, MultiDexSet};
use nexora_shield_package::{read_decoded_entry, ZipDirectory};
use std::path::Path;

const MAX_CONTRACT_ENTRY_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONTRACT_TOTAL_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameKind {
    Class,
    Member,
}

fn name_kind(symbols: &[String]) -> NameKind {
    if symbols
        .iter()
        .any(|name| name.starts_with("class:") || name.starts_with("global-type-ref:"))
    {
        NameKind::Class
    } else {
        NameKind::Member
    }
}

#[derive(Debug, Clone)]
struct ChangedName {
    old: String,
    kind: NameKind,
}

fn guard_text_reference(content: &str, changed: &[ChangedName], source: &str) -> Result<()> {
    for name in changed {
        let old = name.old.as_str();
        let mut aliases = vec![old.to_owned()];
        if name.kind == NameKind::Class {
            let core = old
                .trim_start_matches('[')
                .strip_prefix('L')
                .and_then(|s| s.strip_suffix(';'));
            if let Some(core) = core {
                let dotted = core.replace('/', ".");
                aliases.push(dotted);
                if let Some(simple) = core.rsplit('/').next() {
                    // Android manifests permit both .Relative and bare Class
                    // spellings. False positives are safer than breaking
                    // launcher/service/provider entrypoints.
                    aliases.push(format!(".{simple}"));
                    aliases.push(simple.to_owned());
                }
            }
        }
        let referenced = aliases.iter().any(|candidate| {
            let data = content.as_bytes();
            let target = candidate.as_bytes();
            // Full descriptors/dotted classes can appear as literal values.
            // Simple names must be properly quoted to avoid unrelated text.
            if target.len() < old.len() && name.kind == NameKind::Class {
                ["\"", "'"]
                    .iter()
                    .any(|quote| content.contains(&format!("{quote}{candidate}{quote}")))
            } else {
                data.windows(target.len()).any(|window| window == target)
            }
        });
        if referenced {
            return Err(CoreError::InvalidRequest(format!(
                "O.1.3 external Android binding in {source} needs a keep rule or linked resource rewrite"
            )));
        }
    }
    Ok(())
}

/// Validate every proposed rename against opaque, non-DEX APK contracts.
/// This is intentionally restrictive: no class/name rewrite is treated as
/// Android-installable merely because the DEX checksum and CFG are intact.
pub(crate) fn verify_apk_compatibility(
    path: &Path,
    directory: &ZipDirectory,
    set: &MultiDexSet,
    outputs: &[DexRewriteOutput],
) -> Result<()> {
    let mut changed = Vec::new();
    for output in outputs {
        if let Some(report) = &output.rename_report {
            for record in &report.records {
                changed.push(ChangedName {
                    old: record.old.clone(),
                    kind: name_kind(&record.symbols),
                });
            }
        }
    }
    if changed.is_empty() {
        return Ok(());
    }

    // Reflection API method IDs can exist without literal "forName" strings;
    // the dynamic target is not statically provable from a DEX name table.
    for unit in &set.units {
        let report = CompatibilityAnalyzer::analyze(&unit.dex)
            .map_err(|e| CoreError::InvalidRequest(format!("O.1.3 reflection analysis: {e}")))?;
        if report.reflection_detected {
            return Err(CoreError::InvalidRequest(
                "O.1.3 dynamic reflection prevents safe static symbol relinking".into(),
            ));
        }
        if !report.native_methods.is_empty() {
            return Err(CoreError::InvalidRequest(
                "O.1.3 DEX native-method linkage needs verified JNI registration".into(),
            ));
        }
    }

    verify_non_dex_entries(path, directory, &changed)
}

fn verify_non_dex_entries(
    path: &Path,
    directory: &ZipDirectory,
    changed: &[ChangedName],
) -> Result<()> {
    let mut total = 0_usize;
    let mut found_manifest = false;
    for entry in &directory.entries {
        let name = entry.name.as_str();
        if name == "AndroidManifest.xml" {
            found_manifest = true;
        }
        if nexora_shield_dex::canonical_dex_index(name).is_some() {
            continue;
        }
        let extension = Path::new(name)
            .extension()
            .and_then(|suffix| suffix.to_str());
        if extension.is_some_and(|suffix| suffix.eq_ignore_ascii_case("so"))
            && name.starts_with("lib/")
        {
            return Err(CoreError::InvalidRequest(
                "O.1.3 packaged native library requires JNI binding verification".into(),
            ));
        }
        if name.eq_ignore_ascii_case("resources.arsc") {
            return Err(CoreError::InvalidRequest(
                "O.1.3 compiled resource table has no verified reference remapper".into(),
            ));
        }
        let is_xml = name == "AndroidManifest.xml"
            || extension.is_some_and(|suffix| suffix.eq_ignore_ascii_case("xml"));
        let is_text = is_xml
            || extension.is_some_and(|suffix| {
                ["json", "txt", "properties", "cfg", "ini", "pro"]
                    .iter()
                    .any(|candidate| suffix.eq_ignore_ascii_case(candidate))
            });
        if !is_text {
            // All other entries are copied byte-for-byte. Their dynamic code
            // references cannot be certified by this diagnostic gate.
            continue;
        }
        let size = usize::try_from(entry.uncompressed_size)
            .map_err(|_| CoreError::InvalidRequest("O.1.3 external entry size overflow".into()))?;
        total = total.checked_add(size).ok_or_else(|| {
            CoreError::InvalidRequest("O.1.3 external contract total size overflow".into())
        })?;
        if size > MAX_CONTRACT_ENTRY_BYTES || total > MAX_CONTRACT_TOTAL_BYTES {
            return Err(CoreError::InvalidRequest(
                "O.1.3 external Android contracts exceed safe scan limits".into(),
            ));
        }
        let bytes = read_decoded_entry(path, entry, MAX_CONTRACT_ENTRY_BYTES)?;
        if is_xml && bytes.starts_with(&[0x03, 0x00, 0x08, 0x00]) {
            return Err(CoreError::InvalidRequest(
                "O.1.3 binary Android XML requires a verified reference remapper".into(),
            ));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            CoreError::InvalidRequest(
                "O.1.3 non-UTF8 XML/configuration needs a verified reference remapper".into(),
            )
        })?;
        if is_xml && !text.trim_start().starts_with('<') {
            return Err(CoreError::InvalidRequest(
                "O.1.3 unrecognized Android XML format".into(),
            ));
        }
        guard_text_reference(text, changed, name)?;
    }
    if !found_manifest {
        return Err(CoreError::InvalidRequest(
            "O.1.3 AndroidManifest.xml is missing".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{guard_text_reference, ChangedName, NameKind};

    fn class() -> Vec<ChangedName> {
        vec![ChangedName {
            old: "Lcom/test/A;".into(),
            kind: NameKind::Class,
        }]
    }

    #[test]
    fn o13_manifest_application_and_relative_activity_are_rejected() {
        assert!(guard_text_reference(
            r#"<manifest package="com.test"><application android:name=".A"/></manifest>"#,
            &class(),
            "AndroidManifest.xml"
        )
        .is_err());
        assert!(guard_text_reference(
            r#"<manifest><activity android:name="com.test.A"/></manifest>"#,
            &class(),
            "AndroidManifest.xml"
        )
        .is_err());
        assert!(guard_text_reference(
            r#"<manifest><provider android:name="Lcom/test/A;"/></manifest>"#,
            &class(),
            "AndroidManifest.xml"
        )
        .is_err());
    }

    #[test]
    fn o13_xml_callback_and_config_class_reference_are_rejected() {
        let member = [ChangedName {
            old: "submit".into(),
            kind: NameKind::Member,
        }];
        assert!(guard_text_reference(
            r#"<Button android:onClick="submit"/>"#,
            &member,
            "res/layout/login.xml"
        )
        .is_err());
        assert!(
            guard_text_reference(r#"{"class":"com.test.A"}"#, &class(), "assets/config.json")
                .is_err()
        );
    }

    #[test]
    fn o13_unreferenced_plain_manifest_is_allowed() {
        assert!(guard_text_reference(
            r#"<manifest package="com.example"><application android:label="Title"/></manifest>"#,
            &class(),
            "AndroidManifest.xml"
        )
        .is_ok());
    }
}
