use crate::model::{DexFile, ReferenceKind};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GraphNode {
    Class(u32),
    Type(u32),
    Field(u32),
    Method(u32),
    Proto(u32),
    String(u32),
    CallSite(u32),
    MethodHandle(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdgeKind {
    Defines,
    Owner,
    Name,
    Superclass,
    FieldType,
    ReturnType,
    ParameterType,
    CodeReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReferenceEdge {
    pub from: GraphNode,
    pub to: GraphNode,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceGraph {
    pub nodes: BTreeSet<GraphNode>,
    pub edges: BTreeSet<ReferenceEdge>,
}

impl ReferenceGraph {
    #[must_use]
    pub fn build(dex: &DexFile) -> Self {
        let mut nodes = BTreeSet::new();
        let mut edges = BTreeSet::new();

        for (index, type_id) in dex.types.iter().enumerate() {
            let type_index = index as u32;
            nodes.insert(GraphNode::Type(type_index));
            nodes.insert(GraphNode::String(type_id.descriptor_idx));
            edges.insert(ReferenceEdge {
                from: GraphNode::Type(type_index),
                to: GraphNode::String(type_id.descriptor_idx),
                kind: EdgeKind::Name,
            });
        }

        for (index, proto) in dex.protos.iter().enumerate() {
            let proto_index = index as u32;
            nodes.insert(GraphNode::Proto(proto_index));
            edges.insert(ReferenceEdge {
                from: GraphNode::Proto(proto_index),
                to: GraphNode::Type(proto.return_type_idx),
                kind: EdgeKind::ReturnType,
            });
            for parameter in &proto.parameters {
                edges.insert(ReferenceEdge {
                    from: GraphNode::Proto(proto_index),
                    to: GraphNode::Type(u32::from(*parameter)),
                    kind: EdgeKind::ParameterType,
                });
            }
        }

        for (index, field) in dex.fields.iter().enumerate() {
            let field_index = index as u32;
            nodes.insert(GraphNode::Field(field_index));
            edges.insert(ReferenceEdge {
                from: GraphNode::Field(field_index),
                to: GraphNode::Type(u32::from(field.class_idx)),
                kind: EdgeKind::Owner,
            });
            edges.insert(ReferenceEdge {
                from: GraphNode::Field(field_index),
                to: GraphNode::Type(u32::from(field.type_idx)),
                kind: EdgeKind::FieldType,
            });
            edges.insert(ReferenceEdge {
                from: GraphNode::Field(field_index),
                to: GraphNode::String(field.name_idx),
                kind: EdgeKind::Name,
            });
        }

        for (index, method) in dex.methods.iter().enumerate() {
            let method_index = index as u32;
            nodes.insert(GraphNode::Method(method_index));
            edges.insert(ReferenceEdge {
                from: GraphNode::Method(method_index),
                to: GraphNode::Type(u32::from(method.class_idx)),
                kind: EdgeKind::Owner,
            });
            edges.insert(ReferenceEdge {
                from: GraphNode::Method(method_index),
                to: GraphNode::Proto(u32::from(method.proto_idx)),
                kind: EdgeKind::Defines,
            });
            edges.insert(ReferenceEdge {
                from: GraphNode::Method(method_index),
                to: GraphNode::String(method.name_idx),
                kind: EdgeKind::Name,
            });
        }

        for class in &dex.classes {
            nodes.insert(GraphNode::Class(class.class_idx));
            edges.insert(ReferenceEdge {
                from: GraphNode::Class(class.class_idx),
                to: GraphNode::Type(class.class_idx),
                kind: EdgeKind::Defines,
            });
            if class.superclass_idx != crate::model::NO_INDEX {
                edges.insert(ReferenceEdge {
                    from: GraphNode::Class(class.class_idx),
                    to: GraphNode::Type(class.superclass_idx),
                    kind: EdgeKind::Superclass,
                });
            }
        }

        for data in dex.class_data.values() {
            for encoded in data.methods() {
                let Some(code) = dex.code_items.get(&encoded.code_off) else {
                    continue;
                };
                let from = GraphNode::Method(encoded.method_idx);
                for instruction in &code.instructions {
                    for reference in [instruction.reference, instruction.secondary_reference]
                        .into_iter()
                        .flatten()
                    {
                        let target = node_for_reference(reference.0, reference.1);
                        nodes.insert(target);
                        edges.insert(ReferenceEdge {
                            from,
                            to: target,
                            kind: EdgeKind::CodeReference,
                        });
                    }
                }
            }
        }

        Self { nodes, edges }
    }

    #[must_use]
    pub fn outgoing(&self, node: GraphNode) -> Vec<ReferenceEdge> {
        self.edges
            .iter()
            .copied()
            .filter(|edge| edge.from == node)
            .collect()
    }

    #[must_use]
    pub fn incoming(&self, node: GraphNode) -> Vec<ReferenceEdge> {
        self.edges
            .iter()
            .copied()
            .filter(|edge| edge.to == node)
            .collect()
    }
}

fn node_for_reference(kind: ReferenceKind, index: u32) -> GraphNode {
    match kind {
        ReferenceKind::String => GraphNode::String(index),
        ReferenceKind::Type => GraphNode::Type(index),
        ReferenceKind::Field => GraphNode::Field(index),
        ReferenceKind::Method => GraphNode::Method(index),
        ReferenceKind::Proto => GraphNode::Proto(index),
        ReferenceKind::CallSite => GraphNode::CallSite(index),
        ReferenceKind::MethodHandle => GraphNode::MethodHandle(index),
    }
}
