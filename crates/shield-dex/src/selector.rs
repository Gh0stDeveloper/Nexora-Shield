use crate::error::{DexError, Result};
use crate::model::DexFile;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorKind {
    Any,
    Class,
    Method,
    Field,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    pub kind: SelectorKind,
    pub class_pattern: String,
    pub member_pattern: Option<String>,
}

impl Selector {
    pub fn new(
        kind: SelectorKind,
        class_pattern: impl Into<String>,
        member_pattern: Option<String>,
    ) -> Result<Self> {
        let class_pattern = class_pattern.into();
        validate_selector_pattern(&class_pattern, "class")?;
        if let Some(pattern) = member_pattern.as_deref() {
            validate_selector_pattern(pattern, "member")?;
        }
        if matches!(kind, SelectorKind::Method | SelectorKind::Field)
            && matches!(member_pattern.as_deref(), None | Some(""))
        {
            return Err(DexError::InvalidSelector(
                "member selector requires a member pattern".into(),
            ));
        }
        Ok(Self {
            kind,
            class_pattern,
            member_pattern,
        })
    }
}

const MAX_SELECTOR_PATTERN_BYTES: usize = 256;

fn validate_selector_pattern(pattern: &str, label: &str) -> Result<()> {
    if pattern.is_empty()
        || pattern.len() > MAX_SELECTOR_PATTERN_BYTES
        || pattern
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(DexError::InvalidSelector(format!(
            "{label} selector pattern must be 1..=256 bytes and contain no control characters"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    pub classes: BTreeSet<u32>,
    pub methods: BTreeSet<u32>,
    pub fields: BTreeSet<u32>,
}

impl Selection {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty() && self.methods.is_empty() && self.fields.is_empty()
    }

    pub fn union_with(&mut self, other: &Self) {
        self.classes.extend(other.classes.iter().copied());
        self.methods.extend(other.methods.iter().copied());
        self.fields.extend(other.fields.iter().copied());
    }

    /// Remove excluded targets from this deterministic per-DEX selection.
    pub fn subtract(&mut self, other: &Self) {
        self.classes.retain(|idx| !other.classes.contains(idx));
        self.methods.retain(|idx| !other.methods.contains(idx));
        self.fields.retain(|idx| !other.fields.contains(idx));
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SelectorResolver;

impl SelectorResolver {
    pub fn resolve(dex: &DexFile, selectors: &[Selector]) -> Result<Selection> {
        if selectors.is_empty() {
            return Ok(select_all(dex));
        }

        let mut selection = Selection::default();
        for selector in selectors {
            for class in &dex.classes {
                let descriptor =
                    dex.type_descriptor(class.class_idx)
                        .ok_or(DexError::InvalidIndex {
                            kind: "type",
                            index: class.class_idx,
                        })?;
                if !glob_match(&selector.class_pattern, descriptor) {
                    continue;
                }

                if matches!(selector.kind, SelectorKind::Any | SelectorKind::Class) {
                    selection.classes.insert(class.class_idx);
                }

                if let Some(data) = dex.class_data.get(&class.class_idx) {
                    if matches!(selector.kind, SelectorKind::Any | SelectorKind::Method) {
                        for encoded in data.methods() {
                            let name = dex.method_name(encoded.method_idx).ok_or(
                                DexError::InvalidIndex {
                                    kind: "method",
                                    index: encoded.method_idx,
                                },
                            )?;
                            if selector
                                .member_pattern
                                .as_deref()
                                .map_or(true, |pattern| glob_match(pattern, name))
                            {
                                selection.methods.insert(encoded.method_idx);
                            }
                        }
                    }
                    if matches!(selector.kind, SelectorKind::Any | SelectorKind::Field) {
                        for encoded in data.static_fields.iter().chain(&data.instance_fields) {
                            let name = dex.field_name(encoded.field_idx).ok_or(
                                DexError::InvalidIndex {
                                    kind: "field",
                                    index: encoded.field_idx,
                                },
                            )?;
                            if selector
                                .member_pattern
                                .as_deref()
                                .map_or(true, |pattern| glob_match(pattern, name))
                            {
                                selection.fields.insert(encoded.field_idx);
                            }
                        }
                    }
                }
            }
        }
        Ok(selection)
    }
}

fn select_all(dex: &DexFile) -> Selection {
    Selection {
        classes: dex.classes.iter().map(|class| class.class_idx).collect(),
        methods: dex
            .class_data
            .values()
            .flat_map(|data| data.methods().map(|method| method.method_idx))
            .collect(),
        fields: dex
            .class_data
            .values()
            .flat_map(|data| data.static_fields.iter().chain(&data.instance_fields))
            .map(|field| field.field_idx)
            .collect(),
    }
}

/// Match '*' and '?' without a quadratic dynamic-programming table.
/// Matching is byte-oriented, consistent with DEX identifier names.
#[must_use]
pub fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut pi = 0_usize;
    let mut vi = 0_usize;
    let mut last_star = None;
    let mut retry_value = 0_usize;
    while vi < value.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == value[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            last_star = Some(pi);
            pi += 1;
            retry_value = vi;
        } else if let Some(star) = last_star {
            pi = star + 1;
            retry_value += 1;
            vi = retry_value;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::{glob_match, Selector, SelectorKind};

    #[test]
    fn glob_matching_is_deterministic() {
        assert!(glob_match("Lcom/example/*;", "Lcom/example/App;"));
        assert!(glob_match("*Service;", "Lx/y/SyncService;"));
        assert!(glob_match("get?ser", "getUser"));
        assert!(!glob_match("set*", "getUser"));
        assert!(glob_match("*", &"x".repeat(1_000_000)));
        assert!(!glob_match("*Impossible", &"x".repeat(1_000_000)));
    }

    #[test]
    fn reject_malformed_or_unbounded_selector_patterns() {
        assert!(Selector::new(SelectorKind::Class, "", None).is_err());
        assert!(Selector::new(SelectorKind::Class, "a".repeat(257), None).is_err());
        assert!(Selector::new(SelectorKind::Class, "Lfoo;\0", None).is_err());
        assert!(Selector::new(SelectorKind::Method, "Lcom/*;", Some("m".repeat(257))).is_err());
        assert!(Selector::new(SelectorKind::Method, "Lcom/*;", None).is_err());
    }
}
