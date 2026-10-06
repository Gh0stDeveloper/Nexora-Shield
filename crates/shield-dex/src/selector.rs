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
        if class_pattern.is_empty() {
            return Err(DexError::InvalidSelector(
                "class pattern must not be empty".into(),
            ));
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

                if matches!(selector.kind, SelectorKind::Any | SelectorKind::Method) {
                    for (index, method) in dex.methods.iter().enumerate() {
                        if u32::from(method.class_idx) != class.class_idx {
                            continue;
                        }
                        let name = dex.string(method.name_idx).ok_or(DexError::InvalidIndex {
                            kind: "string",
                            index: method.name_idx,
                        })?;
                        if match selector.member_pattern.as_deref() {
                            None => true,
                            Some(pattern) => glob_match(pattern, name),
                        } {
                            selection.methods.insert(index as u32);
                        }
                    }
                }

                if matches!(selector.kind, SelectorKind::Any | SelectorKind::Field) {
                    for (index, field) in dex.fields.iter().enumerate() {
                        if u32::from(field.class_idx) != class.class_idx {
                            continue;
                        }
                        let name = dex.string(field.name_idx).ok_or(DexError::InvalidIndex {
                            kind: "string",
                            index: field.name_idx,
                        })?;
                        if match selector.member_pattern.as_deref() {
                            None => true,
                            Some(pattern) => glob_match(pattern, name),
                        } {
                            selection.fields.insert(index as u32);
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
        methods: (0..dex.methods.len()).map(|index| index as u32).collect(),
        fields: (0..dex.fields.len()).map(|index| index as u32).collect(),
    }
}

#[must_use]
pub fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut table = vec![vec![false; value.len() + 1]; pattern.len() + 1];
    table[0][0] = true;

    for index in 1..=pattern.len() {
        if pattern[index - 1] == b'*' {
            table[index][0] = table[index - 1][0];
        }
    }

    for pattern_index in 1..=pattern.len() {
        for value_index in 1..=value.len() {
            table[pattern_index][value_index] = match pattern[pattern_index - 1] {
                b'*' => {
                    table[pattern_index - 1][value_index] || table[pattern_index][value_index - 1]
                }
                b'?' => table[pattern_index - 1][value_index - 1],
                byte => byte == value[value_index - 1] && table[pattern_index - 1][value_index - 1],
            };
        }
    }

    table[pattern.len()][value.len()]
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn glob_matching_is_deterministic() {
        assert!(glob_match("Lcom/example/*;", "Lcom/example/App;"));
        assert!(glob_match("*Service;", "Lx/y/SyncService;"));
        assert!(glob_match("get?ser", "getUser"));
        assert!(!glob_match("set*", "getUser"));
    }
}
