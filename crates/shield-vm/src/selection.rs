use crate::error::{Result, VmError};
use nexora_shield_dex::{DexFile, Selector, SelectorKind, SelectorResolver};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmSelectionMode {
    ConfigOnly,
    AnnotationOnly,
    ConfigOrAnnotation,
    ConfigAndAnnotation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmSelector {
    pub class_pattern: String,
    pub method_pattern: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmSelectionConfig {
    pub enabled: bool,
    pub mode: VmSelectionMode,
    pub selectors: Vec<VmSelector>,
    pub annotation_descriptor: String,
}

impl Default for VmSelectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: VmSelectionMode::ConfigOnly,
            selectors: Vec::new(),
            annotation_descriptor: "Ldev/nexora/shield/Virtualize;".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionPlan {
    pub annotation_descriptor: String,
    pub selected_methods: BTreeSet<u32>,
    pub selected_by_config: BTreeSet<u32>,
    pub selected_by_annotation: BTreeSet<u32>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SelectionPlanner;

impl SelectionPlanner {
    pub fn plan(
        dex: &DexFile,
        annotated_methods: &BTreeSet<u32>,
        config: &VmSelectionConfig,
    ) -> Result<SelectionPlan> {
        if !config.enabled {
            return Ok(SelectionPlan {
                annotation_descriptor: config.annotation_descriptor.clone(),
                selected_methods: BTreeSet::new(),
                selected_by_config: BTreeSet::new(),
                selected_by_annotation: BTreeSet::new(),
            });
        }

        if config.annotation_descriptor.trim().is_empty() {
            return Err(VmError::InvalidSelector(
                "annotation descriptor must not be empty".to_owned(),
            ));
        }

        let mut selected_by_config = BTreeSet::new();
        for selector in &config.selectors {
            if selector.class_pattern.trim().is_empty()
                || selector.method_pattern.trim().is_empty()
            {
                return Err(VmError::InvalidSelector(
                    "class and method patterns must not be empty".to_owned(),
                ));
            }
            let dex_selector = Selector::new(
                SelectorKind::Method,
                selector.class_pattern.clone(),
                Some(selector.method_pattern.clone()),
            )
            .map_err(|error| VmError::InvalidSelector(error.to_string()))?;
            let selection = SelectorResolver::resolve(dex, &[dex_selector])
                .map_err(|error| VmError::InvalidSelector(error.to_string()))?;
            selected_by_config.extend(selection.methods);
        }

        let selected_by_annotation = annotated_methods.clone();
        let selected_methods = match config.mode {
            VmSelectionMode::ConfigOnly => selected_by_config.clone(),
            VmSelectionMode::AnnotationOnly => selected_by_annotation.clone(),
            VmSelectionMode::ConfigOrAnnotation => selected_by_config
                .union(&selected_by_annotation)
                .copied()
                .collect(),
            VmSelectionMode::ConfigAndAnnotation => selected_by_config
                .intersection(&selected_by_annotation)
                .copied()
                .collect(),
        };

        Ok(SelectionPlan {
            annotation_descriptor: config.annotation_descriptor.clone(),
            selected_methods,
            selected_by_config,
            selected_by_annotation,
        })
    }
}
