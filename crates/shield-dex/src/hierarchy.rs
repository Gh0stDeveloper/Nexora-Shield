//! Local class/interface graph for conservative DEX member binding.
//!
//! Unknown Android/SDK ancestors are not treated as closed-world contracts.
use crate::error::{DexError, Result};
use crate::model::DexFile;
use crate::multidex::MultiDexSet;
use std::collections::{BTreeMap, BTreeSet};

const ACC_INTERFACE: u32 = 0x0200;
const MAX_DEPTH: usize = 128;
const OBJECT: &str = "Ljava/lang/Object;";

#[derive(Debug)]
struct Node {
    parent: Option<String>,
    interfaces: Vec<String>,
    is_interface: bool,
}

#[derive(Debug)]
pub(crate) struct DexHierarchy {
    nodes: BTreeMap<String, Node>,
}

impl DexHierarchy {
    pub(crate) fn build(set: &MultiDexSet) -> Result<Self> {
        let mut nodes = BTreeMap::new();
        for unit in &set.units {
            let dex = &unit.dex;
            for class in &dex.classes {
                let name = descriptor(dex, class.class_idx)?;
                let parent = (class.superclass_idx != crate::model::NO_INDEX)
                    .then(|| descriptor(dex, class.superclass_idx).map(str::to_owned))
                    .transpose()?;
                let mut interfaces = Vec::new();
                if class.interfaces_off != 0 {
                    let at = usize::try_from(class.interfaces_off).map_err(|_| {
                        DexError::UnsafeRename("interface type-list offset overflow".into())
                    })?;
                    let count = read_u32(&dex.bytes, at)?;
                    let count = usize::try_from(count).map_err(|_| {
                        DexError::UnsafeRename("interface type-list length overflow".into())
                    })?;
                    if count > dex.types.len() {
                        return Err(DexError::UnsafeRename(
                            "interface type-list exceeds DEX type count".into(),
                        ));
                    }
                    for index in 0..count {
                        let byte = at
                            .checked_add(4)
                            .and_then(|pos| pos.checked_add(index * 2))
                            .ok_or_else(|| {
                                DexError::UnsafeRename("interface offset overflow".into())
                            })?;
                        let item = read_u16(&dex.bytes, byte)?;
                        interfaces.push(descriptor(dex, u32::from(item))?.to_owned());
                    }
                }
                interfaces.sort();
                if interfaces.windows(2).any(|w| w[0] == w[1]) {
                    return Err(DexError::UnsafeRename(
                        "duplicate interface in DEX hierarchy".into(),
                    ));
                }
                nodes.insert(
                    name.to_owned(),
                    Node {
                        parent,
                        interfaces,
                        is_interface: class.access_flags & ACC_INTERFACE != 0,
                    },
                );
            }
        }
        Ok(Self { nodes })
    }

    /// Local parents and interface contracts reachable from this class,
    /// including itself. Invalid cyclic graphs fail closed.
    pub(crate) fn closure(&self, owner: &str) -> Result<BTreeSet<String>> {
        let mut resolved = BTreeSet::new();
        let mut active = BTreeSet::new();
        self.visit(owner, &mut resolved, &mut active, 0)?;
        Ok(resolved)
    }

    fn visit(
        &self,
        owner: &str,
        resolved: &mut BTreeSet<String>,
        active: &mut BTreeSet<String>,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(DexError::UnsafeRename(
                "class/interface hierarchy exceeds supported depth".into(),
            ));
        }
        if active.contains(owner) {
            return Err(DexError::UnsafeRename(
                "cyclic DEX class/interface hierarchy".into(),
            ));
        }
        if resolved.contains(owner) {
            return Ok(());
        }
        active.insert(owner.to_owned());
        if let Some(node) = self.nodes.get(owner) {
            if let Some(parent) = &node.parent {
                self.visit(parent, resolved, active, depth + 1)?;
            }
            for interface in &node.interfaces {
                self.visit(interface, resolved, active, depth + 1)?;
            }
        }
        active.remove(owner);
        resolved.insert(owner.to_owned());
        Ok(())
    }

    /// Only locally-known superclasses/interfaces and java.lang.Object are
    /// closed enough to rename virtual methods. External contracts stay intact.
    pub(crate) fn closed(&self, owner: &str) -> Result<bool> {
        Ok(self
            .closure(owner)?
            .iter()
            .all(|name| name == OBJECT || self.nodes.contains_key(name)))
    }

    /// Most-specific class definition first, then inherited definitions;
    /// interface contracts are handled separately by the member planner.
    pub(crate) fn parents(&self, owner: &str) -> Result<Vec<String>> {
        let mut chain = Vec::new();
        let mut visited = BTreeSet::new();
        let mut cursor = owner.to_owned();
        while let Some(node) = self.nodes.get(&cursor) {
            if !visited.insert(cursor.clone()) || chain.len() >= MAX_DEPTH {
                return Err(DexError::UnsafeRename(
                    "cyclic or oversized superclass chain".into(),
                ));
            }
            if let Some(parent) = node.parent.as_deref() {
                chain.push(parent.to_owned());
                cursor.clear();
                cursor.push_str(parent);
            } else {
                break;
            }
        }
        Ok(chain)
    }

    pub(crate) fn interfaces(&self, owner: &str) -> Result<BTreeSet<String>> {
        Ok(self
            .closure(owner)?
            .into_iter()
            .filter(|candidate| {
                self.nodes
                    .get(candidate)
                    .is_some_and(|node| node.is_interface)
            })
            .collect())
    }

    /// Includes a shared local descendant, important when an inherited
    /// implementation satisfies an interface declared by the descendant.
    pub(crate) fn connected(&self, first: &str, second: &str) -> Result<bool> {
        if first == second {
            return Ok(true);
        }
        for owner in self.nodes.keys() {
            let closure = self.closure(owner)?;
            if closure.contains(first) && closure.contains(second) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn descriptor(dex: &DexFile, index: u32) -> Result<&str> {
    dex.type_descriptor(index).ok_or(DexError::InvalidIndex {
        kind: "type",
        index,
    })
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32> {
    let raw = bytes
        .get(
            at..at
                .checked_add(4)
                .ok_or_else(|| DexError::UnsafeRename("interface size offset overflow".into()))?,
        )
        .ok_or_else(|| DexError::UnsafeRename("invalid interface type-list size".into()))?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u16(bytes: &[u8], at: usize) -> Result<u16> {
    let raw = bytes
        .get(
            at..at
                .checked_add(2)
                .ok_or_else(|| DexError::UnsafeRename("interface item offset overflow".into()))?,
        )
        .ok_or_else(|| DexError::UnsafeRename("invalid interface type-list item".into()))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}
