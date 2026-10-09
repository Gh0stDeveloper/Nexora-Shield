use crate::error::{DexError, Result};
use crate::model::{DexFile, ReferenceKind, ACC_NATIVE};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompatibilityReport {
    pub reflection_detected: bool,
    pub native_methods: BTreeSet<u32>,
    pub protected_string_indices: BTreeSet<u32>,
    pub reasons: BTreeMap<u32, Vec<String>>,
}

impl CompatibilityReport {
    fn protect(&mut self, string_idx: u32, reason: impl Into<String>) {
        self.protected_string_indices.insert(string_idx);
        self.reasons
            .entry(string_idx)
            .or_default()
            .push(reason.into());
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CompatibilityAnalyzer;

impl CompatibilityAnalyzer {
    pub fn analyze(dex: &DexFile) -> Result<CompatibilityReport> {
        let mut report = CompatibilityReport::default();
        let runtime_strings = runtime_string_indices(dex);
        // A literal referenced by const-string is observable at runtime even
        // without an obvious reflection indicator. Never rewrite its backing
        // string table slot while renaming a coincident symbol.
        for index in &runtime_strings {
            report.protect(*index, "runtime const-string literal");
        }

        report.reflection_detected = runtime_strings
            .iter()
            .any(|index| dex.string(*index).is_some_and(is_reflection_indicator))
            || dex.methods.iter().any(|method| {
                dex.type_descriptor(u32::from(method.class_idx))
                    .zip(dex.string(method.name_idx))
                    .is_some_and(|(owner, name)| is_dynamic_lookup_api(owner, name))
            });

        for data in dex.class_data.values() {
            for encoded in data.methods() {
                if encoded.access_flags & ACC_NATIVE == 0 {
                    continue;
                }
                report.native_methods.insert(encoded.method_idx);
                let method =
                    dex.methods
                        .get(encoded.method_idx as usize)
                        .ok_or(DexError::InvalidIndex {
                            kind: "method",
                            index: encoded.method_idx,
                        })?;
                report.protect(method.name_idx, "JNI/native method name");
                let class_type =
                    dex.types
                        .get(method.class_idx as usize)
                        .ok_or(DexError::InvalidIndex {
                            kind: "type",
                            index: u32::from(method.class_idx),
                        })?;
                report.protect(class_type.descriptor_idx, "JNI/native declaring class");
            }
        }

        if report.reflection_detected {
            let runtime_values = runtime_strings
                .iter()
                .filter_map(|index| dex.string(*index).map(|value| (*index, value)))
                .collect::<Vec<_>>();

            for class in &dex.classes {
                let type_id = &dex.types[class.class_idx as usize];
                let descriptor =
                    dex.string(type_id.descriptor_idx)
                        .ok_or(DexError::InvalidIndex {
                            kind: "string",
                            index: type_id.descriptor_idx,
                        })?;
                let dotted = descriptor_to_dotted(descriptor);
                if runtime_values
                    .iter()
                    .any(|(_, value)| *value == dotted || *value == descriptor)
                {
                    report.protect(type_id.descriptor_idx, "reflection-visible class literal");
                }
            }

            for method in &dex.methods {
                if runtime_strings.contains(&method.name_idx) {
                    report.protect(method.name_idx, "reflection-visible method literal");
                }
            }
            for field in &dex.fields {
                if runtime_strings.contains(&field.name_idx) {
                    report.protect(field.name_idx, "reflection-visible field literal");
                }
            }
        }

        Ok(report)
    }
}

/// A method-id referencing a runtime lookup API is enough to conservatively
/// identify dynamic name resolution, even without a literal `const-string`.
fn is_dynamic_lookup_api(owner: &str, name: &str) -> bool {
    match owner {
        "Ljava/lang/Class;" => matches!(
            name,
            "forName"
                | "getMethod"
                | "getDeclaredMethod"
                | "getField"
                | "getDeclaredField"
                | "getConstructor"
                | "getDeclaredConstructor"
        ),
        "Ljava/lang/ClassLoader;" => matches!(name, "loadClass" | "findClass"),
        "Ljava/lang/invoke/MethodHandles$Lookup;" => matches!(
            name,
            "findVirtual"
                | "findStatic"
                | "findSpecial"
                | "findGetter"
                | "findSetter"
                | "findStaticGetter"
                | "findStaticSetter"
        ),
        "Ljava/lang/reflect/Proxy;" => name == "newProxyInstance",
        _ => false,
    }
}

fn runtime_string_indices(dex: &DexFile) -> BTreeSet<u32> {
    dex.code_items
        .values()
        .flat_map(|code| code.instructions.iter())
        .filter_map(|instruction| match instruction.reference {
            Some((ReferenceKind::String, index)) => Some(index),
            _ => None,
        })
        .collect()
}

fn is_reflection_indicator(value: &str) -> bool {
    matches!(
        value,
        "forName"
            | "getMethod"
            | "getDeclaredMethod"
            | "getField"
            | "getDeclaredField"
            | "getConstructor"
            | "getDeclaredConstructor"
            | "java.lang.Class"
            | "java.lang.reflect.Method"
            | "java.lang.reflect.Field"
            | "java/lang/reflect/Method"
            | "java/lang/reflect/Field"
    )
}

#[cfg(test)]
mod android_reflection_tests {
    use super::is_dynamic_lookup_api;

    #[test]
    fn o13_reflective_api_id_without_const_string_is_detected() {
        for (owner, name) in [
            ("Ljava/lang/Class;", "forName"),
            ("Ljava/lang/Class;", "getDeclaredMethod"),
            ("Ljava/lang/Class;", "getDeclaredField"),
            ("Ljava/lang/ClassLoader;", "loadClass"),
            ("Ljava/lang/invoke/MethodHandles$Lookup;", "findVirtual"),
            ("Ljava/lang/reflect/Proxy;", "newProxyInstance"),
        ] {
            assert!(is_dynamic_lookup_api(owner, name));
        }
    }

    #[test]
    fn o13_non_reflective_method_ids_do_not_trigger_global_guard() {
        assert!(!is_dynamic_lookup_api("Lcom/test/A;", "run"));
        assert!(!is_dynamic_lookup_api("Ljava/lang/Class;", "getName"));
        assert!(!is_dynamic_lookup_api(
            "Ljava/lang/ClassLoader;",
            "getParent"
        ));
    }
}

fn descriptor_to_dotted(descriptor: &str) -> String {
    descriptor
        .strip_prefix('L')
        .and_then(|value| value.strip_suffix(';'))
        .unwrap_or(descriptor)
        .replace('/', ".")
}
