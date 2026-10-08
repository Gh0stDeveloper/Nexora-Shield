//! Immutable, bounded include/exclude selectors for APK DEX preflight.
//! A selector that matches nothing across all DEX units is a configuration error.

use crate::{CoreError, Result};
use nexora_shield_dex::Selector;

pub const MAX_DEX_SELECTOR_RULES: usize = 128;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DexSelectorPolicy {
    includes: Vec<Selector>,
    excludes: Vec<Selector>,
}

impl DexSelectorPolicy {
    /// Add one positive selector. Duplicate and oversized policies fail closed.
    ///
    /// # Errors
    ///
    /// Rejects invalid patterns, duplicates and more than 128 rules.
    pub fn add_include(&mut self, selector: Selector) -> Result<()> {
        self.add(selector, false)
    }

    /// Add one negative selector. It is applied after all positive selectors.
    ///
    /// # Errors
    ///
    /// Rejects invalid patterns, duplicates and more than 128 rules.
    pub fn add_exclude(&mut self, selector: Selector) -> Result<()> {
        self.add(selector, true)
    }

    fn add(&mut self, selector: Selector, excluded: bool) -> Result<()> {
        // Re-validate public Selector fields: callers may construct a Selector
        // without using Selector::new.
        nexora_shield_dex::Selector::new(
            selector.kind,
            selector.class_pattern.clone(),
            selector.member_pattern.clone(),
        )
        .map_err(|error| CoreError::InvalidRequest(error.to_string()))?;
        if self.includes.len() + self.excludes.len() >= MAX_DEX_SELECTOR_RULES {
            return Err(CoreError::InvalidRequest(format!(
                "maximum {MAX_DEX_SELECTOR_RULES} DEX selector rules exceeded"
            )));
        }
        let target = if excluded {
            &mut self.excludes
        } else {
            &mut self.includes
        };
        if target.contains(&selector) {
            return Err(CoreError::InvalidRequest(
                "duplicate DEX selector rule".into(),
            ));
        }
        target.push(selector);
        Ok(())
    }

    #[must_use]
    pub fn includes(&self) -> &[Selector] {
        &self.includes
    }

    #[must_use]
    pub fn excludes(&self) -> &[Selector] {
        &self.excludes
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.includes.is_empty() && self.excludes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{DexSelectorPolicy, MAX_DEX_SELECTOR_RULES};
    use nexora_shield_dex::{Selector, SelectorKind};

    #[test]
    fn accepts_unique_bounded_rules_and_rejects_duplicates() {
        let mut policy = DexSelectorPolicy::default();
        let selector = Selector::new(SelectorKind::Class, "Lcom/example/*;", None)
            .unwrap_or_else(|_| unreachable!());
        assert!(policy.add_include(selector.clone()).is_ok());
        assert!(policy.add_include(selector).is_err());
        assert_eq!(policy.includes().len(), 1);
        assert!(policy.add_exclude(Selector {
            kind: SelectorKind::Class,
            class_pattern: "bad\\0pattern".into(),
            member_pattern: None,
        }).is_err());
        for i in 1..MAX_DEX_SELECTOR_RULES {
            let selector = Selector::new(SelectorKind::Class, format!("Lcom/example/C{i};"), None)
                .unwrap_or_else(|_| unreachable!());
            assert!(policy.add_include(selector).is_ok());
        }
        let overflow = Selector::new(SelectorKind::Class, "Lcom/example/Extra;", None)
            .unwrap_or_else(|_| unreachable!());
        assert!(policy.add_include(overflow).is_err());
    }
}
