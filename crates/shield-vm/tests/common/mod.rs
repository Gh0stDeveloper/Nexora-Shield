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
            Instruction {
                offset: 0,
                opcode: 0x90,
                width: 2,
                pseudo: None,
                branch_targets: Vec::new(),
                reference: None,
                secondary_reference: None,
            },
            Instruction {
                offset: 2,
                opcode: 0x0f,
                width: 1,
                pseudo: None,
                branch_targets: Vec::new(),
                reference: None,
                secondary_reference: None,
            },
        ],
    )
}

pub fn branch_dex() -> DexFile {
    dex_with_code(
        3,
        3,
        vec![0x0038, 0x0003, 0x010f, 0x020f],
        vec![
            Instruction {
                offset: 0,
                opcode: 0x38,
                width: 2,
                pseudo: None,
                branch_targets: vec![3],
                reference: None,
                secondary_reference: None,
            },
            Instruction {
                offset: 2,
                opcode: 0x0f,
                width: 1,
                pseudo: None,
                branch_targets: Vec::new(),
                reference: None,
                secondary_reference: None,
            },
            Instruction {
                offset: 3,
                opcode: 0x0f,
                width: 1,
                pseudo: None,
                branch_targets: Vec::new(),
                reference: None,
                secondary_reference: None,
            },
        ],
    )
}

pub fn orphan_move_result_dex() -> DexFile {
    dex_with_code(
        1,
        0,
        vec![0x000a, 0x000f],
        vec![
            Instruction {
                offset: 0,
                opcode: 0x0a,
                width: 1,
                pseudo: None,
                branch_targets: Vec::new(),
                reference: None,
                secondary_reference: None,
            },
            Instruction {
                offset: 1,
                opcode: 0x0f,
                width: 1,
                pseudo: None,
                branch_targets: Vec::new(),
                reference: None,
                secondary_reference: None,
            },
        ],
    )
}

pub fn unsupported_dex() -> DexFile {
    dex_with_code(
        1,
        0,
        vec![0x0022, 0x0000, 0x000e],
        vec![
            Instruction {
                offset: 0,
                opcode: 0x22,
                width: 2,
                pseudo: None,
                branch_targets: Vec::new(),
                reference: None,
                secondary_reference: None,
            },
            Instruction {
                offset: 2,
                opcode: 0x0e,
                width: 1,
                pseudo: None,
                branch_targets: Vec::new(),
                reference: None,
                secondary_reference: None,
            },
        ],
    )
}

fn dex_with_code(
    registers_size: u16,
    ins_size: u16,
    insns: Vec<u16>,
    instructions: Vec<Instruction>,
) -> DexFile {
    let insns_size = u32::try_from(insns.len()).unwrap_or(u32::MAX);
    let parameter_count = usize::from(ins_size);
    let strings = vec![
        DexString {
            value: "I".to_owned(),
            data_offset: 0,
            data_start: 0,
            byte_len: 1,
            utf16_len: 1,
        },
        DexString {
            value: "LTest;".to_owned(),
            data_offset: 0,
            data_start: 0,
            byte_len: 6,
            utf16_len: 6,
        },
        DexString {
            value: "add".to_owned(),
            data_offset: 0,
            data_start: 0,
            byte_len: 3,
            utf16_len: 3,
        },
    ];

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
        header: DexHeader {
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
        },
        strings,
        types: vec![TypeId { descriptor_idx: 0 }, TypeId { descriptor_idx: 1 }],
        protos: vec![ProtoId {
            shorty_idx: 0,
            return_type_idx: 0,
            parameters_off: 0,
            parameters: vec![0; parameter_count],
        }],
        fields: Vec::new(),
        methods: vec![MethodId {
            class_idx: 1,
            proto_idx: 0,
            name_idx: 2,
        }],
        classes: vec![ClassDef {
            class_idx: 1,
            access_flags: 0,
            superclass_idx: NO_INDEX,
            interfaces_off: 0,
            source_file_idx: NO_INDEX,
            annotations_off: 0,
            class_data_off: 1,
            static_values_off: 0,
        }],
        class_data: BTreeMap::from([(
            1,
            ClassData {
                static_fields: Vec::new(),
                instance_fields: Vec::new(),
                direct_methods: vec![EncodedMethod {
                    method_idx: 0,
                    access_flags: ACC_STATIC,
                    code_off: 1,
                }],
                virtual_methods: Vec::new(),
            },
        )]),
        code_items: BTreeMap::from([(1, code)]),
    }
}
