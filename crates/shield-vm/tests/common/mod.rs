#![allow(dead_code)]

use nexora_shield_dex::{
    ClassData, ClassDef, CodeItem, DexFile, DexHeader, DexString, EncodedMethod, Instruction,
    MethodId, ProtoId, TypeId, ACC_STATIC, DEX_ENDIAN_CONSTANT, DEX_HEADER_SIZE, NO_INDEX,
};
use std::collections::BTreeMap;

pub fn add_dex() -> DexFile {
    dex_with_code(
        3,
        2,
        vec![0x0090, 0x0201, 0x000f],
        vec![
            instruction(0, 0x90, 2, Vec::new()),
            instruction(2, 0x0f, 1, Vec::new()),
        ],
    )
}

pub fn branch_dex() -> DexFile {
    dex_with_code(
        3,
        3,
        vec![0x0038, 0x0003, 0x010f, 0x020f],
        vec![
            instruction(0, 0x38, 2, vec![3]),
            instruction(2, 0x0f, 1, Vec::new()),
            instruction(3, 0x0f, 1, Vec::new()),
        ],
    )
}

pub fn orphan_move_result_dex() -> DexFile {
    dex_with_code(
        1,
        0,
        vec![0x000a, 0x000f],
        vec![
            instruction(0, 0x0a, 1, Vec::new()),
            instruction(1, 0x0f, 1, Vec::new()),
        ],
    )
}

pub fn unsupported_dex() -> DexFile {
    dex_with_code(
        1,
        0,
        vec![0x0022, 0x0000, 0x000e],
        vec![
            instruction(0, 0x22, 2, Vec::new()),
            instruction(2, 0x0e, 1, Vec::new()),
        ],
    )
}

fn instruction(offset: u32, opcode: u8, width: u16, branch_targets: Vec<u32>) -> Instruction {
    Instruction {
        offset,
        opcode,
        width,
        pseudo: None,
        branch_targets,
        reference: None,
        secondary_reference: None,
    }
}

fn dex_with_code(
    registers_size: u16,
    ins_size: u16,
    insns: Vec<u16>,
    instructions: Vec<Instruction>,
) -> DexFile {
    let insns_size = u32::try_from(insns.len()).unwrap_or(u32::MAX);
    let code = CodeItem {
        offset: 1,
        registers_size,
        ins_size,
        outs_size: 0,
        tries_size: 0,
        debug_info_off: 0,
        insns_size,
        insns,
        instructions,
        tries: Vec::new(),
        handlers: Vec::new(),
    };

    DexFile {
        bytes: Vec::new(),
        header: fixture_header(),
        strings: fixture_strings(),
        types: vec![TypeId { descriptor_idx: 0 }, TypeId { descriptor_idx: 1 }],
        protos: vec![ProtoId {
            shorty_idx: 0,
            return_type_idx: 0,
            parameters_off: 0,
            parameters: vec![0; usize::from(ins_size)],
        }],
        fields: Vec::new(),
        methods: vec![MethodId {
            class_idx: 1,
            proto_idx: 0,
            name_idx: 2,
        }],
        classes: vec![fixture_class()],
        class_data: BTreeMap::from([(1, fixture_class_data())]),
        code_items: BTreeMap::from([(1, code)]),
    }
}

fn fixture_header() -> DexHeader {
    DexHeader {
        version: "035".to_owned(),
        checksum: 0,
        signature: [0; 20],
        file_size: DEX_HEADER_SIZE,
        header_size: DEX_HEADER_SIZE,
        endian_tag: DEX_ENDIAN_CONSTANT,
        link_size: 0,
        link_off: 0,
        map_off: 0,
        string_ids_size: 3,
        string_ids_off: 0,
        type_ids_size: 2,
        type_ids_off: 0,
        proto_ids_size: 1,
        proto_ids_off: 0,
        field_ids_size: 0,
        field_ids_off: 0,
        method_ids_size: 1,
        method_ids_off: 0,
        class_defs_size: 1,
        class_defs_off: 0,
        data_size: 0,
        data_off: 0,
    }
}

fn fixture_strings() -> Vec<DexString> {
    [
        ("I", 1_usize, 1_u32),
        ("LTest;", 6, 6),
        ("add", 3, 3),
    ]
    .into_iter()
    .map(|(value, byte_len, utf16_len)| DexString {
        value: value.to_owned(),
        data_offset: 0,
        data_start: 0,
        byte_len,
        utf16_len,
    })
    .collect()
}

fn fixture_class() -> ClassDef {
    ClassDef {
        class_idx: 1,
        access_flags: 0,
        superclass_idx: NO_INDEX,
        interfaces_off: 0,
        source_file_idx: NO_INDEX,
        annotations_off: 0,
        class_data_off: 1,
        static_values_off: 0,
    }
}

fn fixture_class_data() -> ClassData {
    ClassData {
        static_fields: Vec::new(),
        instance_fields: Vec::new(),
        direct_methods: vec![EncodedMethod {
            method_idx: 0,
            access_flags: ACC_STATIC,
            code_off: 1,
        }],
        virtual_methods: Vec::new(),
    }
}
