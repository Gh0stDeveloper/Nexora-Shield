//! Signature-bound method and field planning across canonical DEX units.
//!
//! The fixed-width writer cannot split shared string IDs. In ambiguous cases
//! the linked transform refuses to emit a partially-linked diagnostic APK.
use crate::compatibility::CompatibilityReport;
use crate::error::{DexError, Result};
use crate::model::{DexFile, ACC_NATIVE, ACC_STATIC};
use crate::multidex::MultiDexSet;
use crate::selector::SelectorResolver;
use crate::transform::{is_contract_name, RenameConfig};
use std::collections::{BTreeMap, BTreeSet};

const ACC_PRIVATE: u32 = 0x0002;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Member {
    Method {
        owner: String,
        name: String,
        signature: String,
    },
    Field {
        owner: String,
        name: String,
        field_type: String,
    },
}

impl Member {
    fn name(&self) -> &str {
        match self {
            Self::Method { name, .. } | Self::Field { name, .. } => name,
        }
    }

    fn owner(&self) -> &str {
        match self {
            Self::Method { owner, .. } | Self::Field { owner, .. } => owner,
        }
    }

    fn with_owner(&self, replacement: &str) -> Self {
        let mut key = self.clone();
        match &mut key {
            Self::Method { owner, .. } | Self::Field { owner, .. } => {
                *owner = replacement.to_owned();
            }
        }
        key
    }

}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemberPatch {
    pub(crate) new: String,
    pub(crate) symbols: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct MemberPlan {
    pub(crate) patches: Vec<BTreeMap<u32, MemberPatch>>,
    pub(crate) skipped: Vec<BTreeSet<u32>>,
}

/// Build one binding table from *definitions*, then apply those identities to
/// every method_id/field_id, including imported IDs in other DEX units.
pub(crate) fn plan(
    set: &MultiDexSet,
    config: &RenameConfig,
    compatibility: &[CompatibilityReport],
) -> Result<MemberPlan> {
    let mut selected = Vec::with_capacity(set.units.len());
    for unit in &set.units {
        selected.push(SelectorResolver::resolve(&unit.dex, &config.selectors)?);
    }

    let mut defined = BTreeMap::<Member, bool>::new();
    let mut protected = BTreeSet::<Member>::new();
    for ((unit, selection), report) in set.units.iter().zip(&selected).zip(compatibility) {
        for class in &unit.dex.classes {
            let Some(data) = unit.dex.class_data.get(&class.class_idx) else {
                continue;
            };
            for encoded in &data.direct_methods {
                let method = unit.dex.methods.get(encoded.method_idx as usize).ok_or(
                    DexError::InvalidIndex {
                        kind: "method",
                        index: encoded.method_idx,
                    },
                )?;
                let key = method_key(&unit.dex, encoded.method_idx)?;
                let allowed = config.rename_methods
                    && selection.methods.contains(&encoded.method_idx)
                    && (encoded.access_flags & (ACC_STATIC | ACC_PRIVATE) != 0)
                    && (encoded.access_flags & ACC_NATIVE == 0)
                    && !is_contract_name(key.name())
                    && !report.protected_string_indices.contains(&method.name_idx);
                if defined.insert(key.clone(), allowed).is_some() {
                    return Err(DexError::UnsafeRename(
                        "duplicate defined method identity".into(),
                    ));
                }
                if !allowed {
                    protected.insert(key);
                }
            }
            // Virtual methods can implement an external SDK/interface contract,
            // even when the declaring class is local. Do not rename them until
            // interface/override closure is available for the whole hierarchy.
            for encoded in &data.virtual_methods {
                protected.insert(method_key(&unit.dex, encoded.method_idx)?);
            }
            for encoded in data.static_fields.iter().chain(&data.instance_fields) {
                let field = unit.dex.fields.get(encoded.field_idx as usize).ok_or(
                    DexError::InvalidIndex {
                        kind: "field",
                        index: encoded.field_idx,
                    },
                )?;
                let key = field_key(&unit.dex, encoded.field_idx)?;
                let allowed = config.rename_fields
                    && selection.fields.contains(&encoded.field_idx)
                    && !is_contract_name(key.name())
                    && !report.protected_string_indices.contains(&field.name_idx);
                if defined.insert(key.clone(), allowed).is_some() {
                    return Err(DexError::UnsafeRename(
                        "duplicate defined field identity".into(),
                    ));
                }
                if !allowed {
                    protected.insert(key);
                }
            }
        }
    }

    // All selected symbols with an original spelling receive the same stable
    // generated spelling. Different overloads and shared string IDs thus
    // cannot accidentally acquire different names.
    let requested = defined
        .iter()
        .filter_map(|(member, eligible)| (*eligible).then_some(member.name().to_owned()))
        .collect::<BTreeSet<_>>();
    let mut reserved = set
        .units
        .iter()
        .flat_map(|unit| unit.dex.strings.iter().map(|s| s.value.clone()))
        .collect::<BTreeSet<_>>();
    let mut new_by_name = BTreeMap::new();
    for old in requested {
        if !old.is_ascii() || old.is_empty() {
            return Err(DexError::UnsafeRename(
                "linked member names must be non-empty ASCII in the fixed-layout writer".into(),
            ));
        }
        let mut salt = 0_u64;
        let replacement = loop {
            let candidate = obfuscated_name(&old, config.seed, salt);
            if candidate != old && !reserved.contains(&candidate) {
                break candidate;
            }
            salt += 1;
            if salt > 10_000 {
                return Err(DexError::UnsafeRename(
                    "linked member name space exhausted".into(),
                ));
            }
        };
        reserved.insert(replacement.clone());
        new_by_name.insert(old, replacement);
    }

    // Method/field IDs may encode a subclass even when runtime resolution
    // binds an inherited superclass member. Do not leave such a reference
    // unchanged while renaming its defining member. A complete hierarchy
    // resolver must handle this before the case can be enabled.
    let mut superclass = BTreeMap::<String, String>::new();
    for unit in &set.units {
        for class in &unit.dex.classes {
            if class.superclass_idx == crate::model::NO_INDEX {
                continue;
            }
            let owner = type_name(&unit.dex, class.class_idx)?;
            let parent = type_name(&unit.dex, class.superclass_idx)?;
            superclass.insert(owner.to_owned(), parent.to_owned());
        }
    }

    let mut result = MemberPlan::default();
    for (unit, report) in set.units.iter().zip(compatibility) {
        let mut usage = BTreeMap::<u32, Vec<(Member, bool, String)>>::new();
        for (index, method) in unit.dex.methods.iter().enumerate() {
            let key = method_key(&unit.dex, index as u32)?;
            reject_unmapped_inherited(&key, &defined, &superclass)?;
            let change = defined.get(&key).copied().unwrap_or(false);
            usage.entry(method.name_idx).or_default().push((
                key,
                change,
                format!("method-ref:{index}"),
            ));
        }
        for (index, field) in unit.dex.fields.iter().enumerate() {
            let key = field_key(&unit.dex, index as u32)?;
            reject_unmapped_inherited(&key, &defined, &superclass)?;
            let change = defined.get(&key).copied().unwrap_or(false);
            usage.entry(field.name_idx).or_default().push((
                key,
                change,
                format!("field-ref:{index}"),
            ));
        }
        let mut patches = BTreeMap::new();
        let mut skipped = BTreeSet::new();
        for (index, uses) in usage {
            let wants_change = uses.iter().any(|(_, change, _)| *change);
            if !wants_change {
                if uses.iter().any(|(key, _, _)| protected.contains(key)) {
                    skipped.insert(index);
                }
                continue;
            }
            // A single DEX string ID cannot carry both a renamed local member
            // and an unrenamed external/inherited/other member reference.
            if uses.iter().any(|(_, change, _)| !change) {
                return Err(DexError::UnsafeRename(
                    "shared member string ID binds both renamed and untouched identities".into(),
                ));
            }
            if report.protected_string_indices.contains(&index) {
                return Err(DexError::UnsafeRename(
                    "member name aliases an observable const-string or JNI literal".into(),
                ));
            }
            // The same string ID can also be referenced by a type_id; changing
            // it would mutate a class/proto signature outside the member plan.
            if unit.dex.types.iter().any(|ty| ty.descriptor_idx == index)
                || unit
                    .dex
                    .protos
                    .iter()
                    .any(|proto| proto.shorty_idx == index)
            {
                return Err(DexError::UnsafeRename(
                    "member name string ID aliases a type or prototype descriptor".into(),
                ));
            }
            let name = uses[0].0.name();
            let replacement = new_by_name.get(name).ok_or_else(|| {
                DexError::UnsafeRename("missing global member name assignment".into())
            })?;
            patches.insert(
                index,
                MemberPatch {
                    new: replacement.clone(),
                    symbols: uses.iter().map(|(_, _, label)| label.clone()).collect(),
                },
            );
        }
        result.patches.push(patches);
        result.skipped.push(skipped);
    }
    Ok(result)
}

fn reject_unmapped_inherited(
    member: &Member,
    defined: &BTreeMap<Member, bool>,
    superclass: &BTreeMap<String, String>,
) -> Result<()> {
    if defined.contains_key(member) {
        return Ok(());
    }
    let mut current = member.owner().to_owned();
    let mut visited = BTreeSet::new();
    while let Some(parent) = superclass.get(&current) {
        if !visited.insert(current.clone()) {
            return Err(DexError::UnsafeRename(
                "cyclic class hierarchy during linked member resolution".into(),
            ));
        }
        let ancestor = member.with_owner(parent);
        if defined.get(&ancestor).copied().unwrap_or(false) {
            return Err(DexError::UnsafeRename(
                "inherited method/field reference requires hierarchy-aware linking".into(),
            ));
        }
        if defined.contains_key(&ancestor) {
            return Ok(());
        }
        current.clone_from(parent);
    }
    Ok(())
}

fn method_key(dex: &DexFile, index: u32) -> Result<Member> {
    let method = dex
        .methods
        .get(index as usize)
        .ok_or(DexError::InvalidIndex {
            kind: "method",
            index,
        })?;
    let proto = dex
        .protos
        .get(method.proto_idx as usize)
        .ok_or(DexError::InvalidIndex {
            kind: "proto",
            index: u32::from(method.proto_idx),
        })?;
    let mut signature = String::from("(");
    for parameter in &proto.parameters {
        signature.push_str(type_name(dex, u32::from(*parameter))?);
    }
    signature.push(')');
    signature.push_str(type_name(dex, proto.return_type_idx)?);
    Ok(Member::Method {
        owner: type_name(dex, u32::from(method.class_idx))?.to_owned(),
        name: dex
            .method_name(index)
            .ok_or(DexError::InvalidIndex {
                kind: "method name",
                index,
            })?
            .to_owned(),
        signature,
    })
}

fn field_key(dex: &DexFile, index: u32) -> Result<Member> {
    let field = dex
        .fields
        .get(index as usize)
        .ok_or(DexError::InvalidIndex {
            kind: "field",
            index,
        })?;
    Ok(Member::Field {
        owner: type_name(dex, u32::from(field.class_idx))?.to_owned(),
        name: dex
            .field_name(index)
            .ok_or(DexError::InvalidIndex {
                kind: "field name",
                index,
            })?
            .to_owned(),
        field_type: type_name(dex, u32::from(field.type_idx))?.to_owned(),
    })
}

fn type_name(dex: &DexFile, index: u32) -> Result<&str> {
    dex.type_descriptor(index).ok_or(DexError::InvalidIndex {
        kind: "type",
        index,
    })
}

fn obfuscated_name(original: &str, seed: u64, salt: u64) -> String {
    const FIRST: &[u8; 26] = b"abcdefghijklmnopqrstuvwxyz";
    const REST: &[u8; 37] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
    let mut state = seed ^ salt.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for byte in original.bytes() {
        state ^= u64::from(byte);
        state = state.wrapping_mul(0x100_0000_01b3);
    }
    let mut output = String::with_capacity(original.len());
    for index in 0..original.len() {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let hash = state.wrapping_mul(0x2545_f491_4f6c_dd1d);
        let alphabet = if index == 0 {
            FIRST.as_slice()
        } else {
            REST.as_slice()
        };
        output.push(char::from(
            alphabet[(hash % alphabet.len() as u64) as usize],
        ));
    }
    output
}
