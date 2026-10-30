use super::AndroidRuntimePlan;
use crate::{runtime_smali::refuse, Result};
use nexora_shield_dex::DexParser;
use nexora_shield_package::{read_decoded_entry, read_zip_directory};
use std::collections::BTreeSet;

pub(super) const STREAM: &str = "Ldev/nexora/shield/ResourceInputStream;";
pub(super) const OPEN: &str =
    "Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;";
pub(super) const OPEN_MODE: &str =
    "Landroid/content/res/AssetManager;->open(Ljava/lang/String;I)Ljava/io/InputStream;";

impl AndroidRuntimePlan {
    /// Encrypt explicit raw assets and bind every direct AssetManager.open use site.
    /// # Errors
    /// Rejects native/reflection/dynamic asset access, unsupported descriptors and unobserved accesses.
    pub fn with_protected_assets(mut self, paths: &[String]) -> Result<Self> {
        if paths.is_empty() || !self.assets.is_empty() || self.guard.is_some() {
            return Err(refuse(
                "assets require one explicit selection before guard binding",
            ));
        }
        let directory = read_zip_directory(&self.snapshot.path())?;
        let manifest = directory
            .entries
            .iter()
            .find(|e| e.name == "AndroidManifest.xml")
            .ok_or_else(|| refuse("missing asset manifest"))?;
        let bytes = read_decoded_entry(&self.snapshot.path(), manifest, 16 * 1024 * 1024)?;
        let (_, sdk) = crate::android_binary_xml::runtime_manifest_contract(&bytes)?;
        if sdk < 28 {
            return Err(refuse("asset stream compatibility requires minSdk 28; older stream contracts are unverified"));
        }
        if directory.entries.iter().any(|e| e.name.starts_with("lib/")) {
            return Err(refuse(
                "asset encryption cannot prove existing native access contracts",
            ));
        }
        let opens = inspect_access(&self.units)?;
        let mut unique = BTreeSet::new();
        for path in paths {
            if !unique.insert(path)
                || !path.starts_with("assets/")
                || path.starts_with("assets/nexora-shield/")
            {
                return Err(refuse("duplicate or reserved asset selection"));
            }
            let entry = directory
                .entries
                .iter()
                .find(|e| &e.name == path)
                .ok_or_else(|| refuse("selected asset is missing"))?;
            let bytes = read_decoded_entry(&self.snapshot.path(), entry, 1024 * 1024)?;
            let slot =
                u32::try_from(256 + self.assets.len()).map_err(|_| refuse("too many assets"))?;
            let encrypted = self
                .image
                .protect_resource(slot, path, bytes)
                .map_err(|_| refuse("asset encryption failed"))?;
            self.assets.insert(path.clone(), encrypted);
        }
        self.asset_calls = opens;
        self.context.verify_input_unchanged()?;
        Ok(self)
    }
}

fn inspect_access(units: &[nexora_shield_dex::DexInput]) -> Result<usize> {
    let mut opens = 0;
    for unit in units {
        let dex = DexParser::parse(&unit.bytes).map_err(|_| refuse("invalid asset DEX"))?;
        for t in &dex.types {
            let name = dex
                .string(t.descriptor_idx)
                .ok_or_else(|| refuse("invalid asset type"))?;
            if name == STREAM
                || name.starts_with("Landroid/content/res/AssetManager$")
                || name.starts_with("Ljava/lang/reflect/")
                || name.starts_with("Ljava/lang/invoke/")
                || name.contains("ClassLoader;")
                || name.starts_with("Landroid/webkit/")
                || name.starts_with("Ljava/util/zip/Zip")
                || name.starts_with("Ljava/util/jar/Jar")
            {
                return Err(refuse(
                    "asset stream casts or dynamic access require a verified binder",
                ));
            }
        }
        for method in &dex.methods {
            let owner = dex
                .type_descriptor(u32::from(method.class_idx))
                .ok_or_else(|| refuse("invalid asset owner"))?;
            let name = dex
                .string(method.name_idx)
                .ok_or_else(|| refuse("invalid asset method"))?;
            if owner == "Landroid/content/res/AssetManager;" {
                if name != "open" && name != "list" {
                    return Err(refuse(
                        "unsupported asset file-descriptor or dynamic manager access",
                    ));
                }
                if name == "open" {
                    let proto = &dex.protos[usize::from(method.proto_idx)];
                    let result = dex.type_descriptor(proto.return_type_idx).unwrap_or("");
                    let parameters = proto
                        .parameters
                        .iter()
                        .map(|i| dex.type_descriptor(u32::from(*i)).unwrap_or(""))
                        .collect::<Vec<_>>();
                    if result != "Ljava/io/InputStream;"
                        || !(parameters == ["Ljava/lang/String;"]
                            || parameters == ["Ljava/lang/String;", "I"])
                    {
                        return Err(refuse("unsupported AssetManager.open overload"));
                    }
                }
            }
            if owner == "Ljava/lang/Class;"
                || (owner == "Ljava/lang/Object;" && name == "getClass")
                || name == "createPackageContext"
                || name == "createContextForSplit"
                || name == "getResourcesForApplication"
            {
                return Err(refuse(
                    "foreign or reflective asset manager access requires a verified binder",
                ));
            }
        }
        for code in dex.code_items.values() {
            for instruction in &code.instructions {
                if matches!(instruction.opcode, 0xfa..=0xfd) {
                    return Err(refuse(
                        "dynamic invocation is outside the asset access contract",
                    ));
                }
                if let Some((kind, index)) = instruction.reference {
                    if kind == nexora_shield_dex::ReferenceKind::Method {
                        let m = &dex.methods[index as usize];
                        if dex.type_descriptor(u32::from(m.class_idx))
                            == Some("Landroid/content/res/AssetManager;")
                            && dex.string(m.name_idx) == Some("open")
                        {
                            if !matches!(instruction.opcode, 0x6e | 0x74) {
                                return Err(refuse("unsupported asset dispatch"));
                            }
                            opens += 1;
                        }
                    }
                }
            }
        }
    }
    if opens == 0 {
        return Err(refuse(
            "selected assets have no direct AssetManager.open access",
        ));
    }
    Ok(opens)
}

pub(super) fn rewrite(source: &str) -> Result<(String, usize)> {
    let mut count = 0;
    let mut result = String::new();
    for line in source.lines() {
        let target = if line.trim_end().ends_with(OPEN_MODE) {
            Some((OPEN_MODE,"openAsset(Landroid/content/res/AssetManager;Ljava/lang/String;I)Ljava/io/InputStream;"))
        } else if line.trim_end().ends_with(OPEN) {
            Some((OPEN,"openAsset(Landroid/content/res/AssetManager;Ljava/lang/String;)Ljava/io/InputStream;"))
        } else {
            None
        };
        let line = if let Some((original, replacement)) = target {
            let line = if line.trim_start().starts_with("invoke-virtual/range ") {
                line.replacen("invoke-virtual/range", "invoke-static/range", 1)
            } else if line.trim_start().starts_with("invoke-virtual ") {
                line.replacen("invoke-virtual", "invoke-static", 1)
            } else {
                return Err(refuse("unsupported asset Smali dispatch"));
            };
            count += 1;
            line.replace(
                original,
                &format!("Ldev/nexora/shield/NativeShield;->{replacement}"),
            )
        } else {
            line.to_owned()
        };
        result.push_str(&line);
        result.push('\n');
    }
    Ok((result, count))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn asset_invocations_preserve_registers_range_and_overload_contracts() -> Result<()> {
        let source=format!(".class LA;\ninvoke-virtual {{v1, v2}}, {OPEN}\ninvoke-virtual/range {{v5 .. v7}}, {OPEN_MODE}\nreturn-object v0\n");
        let (updated, count) = rewrite(&source)?;
        assert_eq!(count, 2);
        assert!(updated.contains("invoke-static {v1, v2}, Ldev/nexora/shield/NativeShield;->openAsset(Landroid/content/res/AssetManager;Ljava/lang/String;)Ljava/io/InputStream;"));
        assert!(updated.contains("invoke-static/range {v5 .. v7}, Ldev/nexora/shield/NativeShield;->openAsset(Landroid/content/res/AssetManager;Ljava/lang/String;I)Ljava/io/InputStream;"));
        assert!(updated.ends_with("return-object v0\n"));
        assert!(rewrite(&format!("invoke-direct {{v1,v2}}, {OPEN}")).is_err());
        Ok(())
    }
}
