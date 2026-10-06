use std::collections::BTreeMap;

pub const DEX_HEADER_SIZE: u32 = 0x70;
pub const DEX_ENDIAN_CONSTANT: u32 = 0x1234_5678;
pub const NO_INDEX: u32 = u32::MAX;
pub const ACC_STATIC: u32 = 0x0008;
pub const ACC_NATIVE: u32 = 0x0100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexHeader {
    pub version: String,
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexString {
    pub value: String,
    pub data_offset: u32,
    pub data_start: u32,
    pub byte_len: u32,
    pub utf16_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeId {
    pub descriptor_idx: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoId {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
    pub parameters: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldId {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodId {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassDef {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedField {
    pub field_idx: u32,
    pub access_flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedMethod {
    pub method_idx: u32,
    pub access_flags: u32,
    pub code_off: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassData {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

impl ClassData {
    pub fn methods(&self) -> impl Iterator<Item = &EncodedMethod> {
        self.direct_methods.iter().chain(self.virtual_methods.iter())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler_off: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchHandler {
    pub relative_offset: u32,
    pub typed_handlers: Vec<(u32, u32)>,
    pub catch_all_addr: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceKind {
    String,
    Type,
    Field,
    Method,
    Proto,
    CallSite,
    MethodHandle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PseudoInstruction {
    PackedSwitchPayload,
    SparseSwitchPayload,
    FillArrayDataPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub offset: u32,
    pub opcode: u8,
    pub width: u32,
    pub pseudo: Option<PseudoInstruction>,
    pub branch_targets: Vec<u32>,
    pub reference: Option<(ReferenceKind, u32)>,
    pub secondary_reference: Option<(ReferenceKind, u32)>,
}

impl Instruction {
    #[must_use]
    pub fn end_offset(&self) -> u32 {
        self.offset + self.width
    }

    #[must_use]
    pub fn is_payload(&self) -> bool {
        self.pseudo.is_some()
    }

    #[must_use]
    pub fn is_return_or_throw(&self) -> bool {
        matches!(self.opcode, 0x0e..=0x11 | 0x27) && self.pseudo.is_none()
    }

    #[must_use]
    pub fn is_unconditional_goto(&self) -> bool {
        matches!(self.opcode, 0x28..=0x2a) && self.pseudo.is_none()
    }

    #[must_use]
    pub fn falls_through(&self) -> bool {
        !self.is_return_or_throw() && !self.is_unconditional_goto() && self.pseudo.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeItem {
    pub offset: u32,
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
    pub insns: Vec<u16>,
    pub instructions: Vec<Instruction>,
    pub tries: Vec<TryItem>,
    pub handlers: Vec<CatchHandler>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DexFile {
    pub bytes: Vec<u8>,
    pub header: DexHeader,
    pub strings: Vec<DexString>,
    pub types: Vec<TypeId>,
    pub protos: Vec<ProtoId>,
    pub fields: Vec<FieldId>,
    pub methods: Vec<MethodId>,
    pub classes: Vec<ClassDef>,
    pub class_data: BTreeMap<u32, ClassData>,
    pub code_items: BTreeMap<u32, CodeItem>,
}

impl DexFile {
    #[must_use]
    pub fn string(&self, index: u32) -> Option<&str> {
        self.strings.get(index as usize).map(|value| value.value.as_str())
    }

    #[must_use]
    pub fn type_descriptor(&self, index: u32) -> Option<&str> {
        let type_id = self.types.get(index as usize)?;
        self.string(type_id.descriptor_idx)
    }

    #[must_use]
    pub fn method_name(&self, index: u32) -> Option<&str> {
        let method = self.methods.get(index as usize)?;
        self.string(method.name_idx)
    }

    #[must_use]
    pub fn field_name(&self, index: u32) -> Option<&str> {
        let field = self.fields.get(index as usize)?;
        self.string(field.name_idx)
    }

    #[must_use]
    pub fn encoded_method(&self, method_idx: u32) -> Option<&EncodedMethod> {
        self.class_data
            .values()
            .flat_map(ClassData::methods)
            .find(|method| method.method_idx == method_idx)
    }

    #[must_use]
    pub fn code_for_method(&self, method_idx: u32) -> Option<&CodeItem> {
        let encoded = self.encoded_method(method_idx)?;
        self.code_items.get(&encoded.code_off)
    }
}
