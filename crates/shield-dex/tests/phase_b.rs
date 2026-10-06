#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use nexora_shield_dex::{
    refresh_integrity, ControlFlowGraph, DexInput, DexParser, DexValidator, DexWriter, IrMethod,
    MetadataReducer, MultiDexRewriteConfig, MultiDexSet, ReferenceGraph, RenameConfig, RenamePass,
    Selector, SelectorKind, SelectorResolver, TypeAnalyzer, DEX_ENDIAN_CONSTANT, DEX_HEADER_SIZE,
    NO_INDEX,
};

#[test]
fn parser_validator_cfg_type_ir_and_graph_cover_a_real_code_item() {
    let bytes = build_test_dex("Lcom/test/A;", "run");
    let dex = DexParser::parse(&bytes).expect("parse synthetic DEX");
    let report = DexValidator::validate(&dex).expect("validate synthetic DEX");

    assert_eq!(report.classes, 1);
    assert_eq!(report.methods, 1);
    assert_eq!(report.code_items, 1);
    assert_eq!(dex.type_descriptor(0), Some("Lcom/test/A;"));
    assert_eq!(dex.method_name(0), Some("run"));

    let code = dex.code_for_method(0).expect("method code");
    let cfg = ControlFlowGraph::build(code).expect("CFG");
    assert_eq!(cfg.blocks.len(), 1);
    assert_eq!(cfg.blocks[0].instruction_offsets, vec![0]);

    let types = TypeAnalyzer::analyze(&dex, 0).expect("type analysis");
    assert_eq!(types.blocks.len(), 1);

    let ir = IrMethod::build(&dex, 0).expect("SSA IR");
    assert_eq!(ir.blocks.len(), 1);
    assert_eq!(ir.blocks[0].instructions.len(), 1);

    let graph = ReferenceGraph::build(&dex);
    assert!(!graph.nodes.is_empty());
    assert!(!graph.edges.is_empty());
}

#[test]
fn writer_round_trip_is_byte_stable() {
    let bytes = build_test_dex("Lcom/test/A;", "run");
    let dex = DexParser::parse(&bytes).expect("parse");
    let output = DexWriter::round_trip(&dex).expect("round trip");
    assert_eq!(output, bytes);
}

#[test]
fn selectors_safe_rename_and_metadata_reduction_compose() {
    let bytes = build_test_dex("Lcom/test/A;", "run");
    let dex = DexParser::parse(&bytes).expect("parse");

    let selector = Selector::new(SelectorKind::Method, "Lcom/test/*;", Some("run".to_owned()))
        .expect("selector");
    let selection = SelectorResolver::resolve(&dex, &[selector.clone()]).expect("selection");
    assert!(selection.methods.contains(&0));

    let rename = RenamePass::apply(
        &dex,
        &RenameConfig {
            selectors: vec![selector],
            rename_classes: false,
            rename_methods: true,
            rename_fields: false,
            ..RenameConfig::default()
        },
    )
    .expect("rename");
    assert_eq!(rename.report.records.len(), 1);

    let renamed = DexParser::parse(&rename.bytes).expect("parse renamed");
    assert_ne!(renamed.method_name(0), Some("run"));
    assert_eq!(renamed.method_name(0).expect("renamed name").len(), 3);

    let (reduced_bytes, reduction) =
        MetadataReducer::strip_debug_metadata(&renamed).expect("metadata reduction");
    assert_eq!(reduction.source_files_removed, 1);
    let reduced = DexParser::parse(&reduced_bytes).expect("parse reduced");
    assert_eq!(reduced.classes[0].source_file_idx, NO_INDEX);
}

#[test]
fn canonical_multidex_round_trip_rewrites_every_unit() {
    let primary = build_test_dex("Lcom/test/A;", "run");
    let secondary = build_test_dex("Lcom/test/B;", "go");

    let set = MultiDexSet::parse(vec![
        DexInput {
            name: "classes2.dex".into(),
            bytes: secondary,
        },
        DexInput {
            name: "classes.dex".into(),
            bytes: primary,
        },
    ])
    .expect("multidex parse");

    assert_eq!(set.units[0].name, "classes.dex");
    assert_eq!(set.units[1].name, "classes2.dex");

    let outputs = set
        .rewrite(&MultiDexRewriteConfig {
            rename: Some(RenameConfig::default()),
            strip_metadata: true,
            conservative_cross_dex_reflection: true,
        })
        .expect("multidex rewrite");

    assert_eq!(outputs.len(), 2);
    for output in outputs {
        let parsed = DexParser::parse(&output.bytes).expect("parse rewritten DEX");
        let _ = DexValidator::validate(&parsed).expect("validate rewritten DEX");
    }
}

fn build_test_dex(class_descriptor: &str, method_name: &str) -> Vec<u8> {
    let strings = [
        class_descriptor,
        "Ljava/lang/Object;",
        "V",
        method_name,
        "A.java",
    ];

    let string_ids_off = DEX_HEADER_SIZE;
    let type_ids_off = string_ids_off + strings.len() as u32 * 4;
    let proto_ids_off = type_ids_off + 3 * 4;
    let method_ids_off = proto_ids_off + 12;
    let class_defs_off = method_ids_off + 8;
    let data_off = class_defs_off + 32;

    let mut bytes = vec![0_u8; data_off as usize];
    let mut string_offsets = Vec::with_capacity(strings.len());

    for value in strings {
        string_offsets.push(bytes.len() as u32);
        write_uleb128(&mut bytes, value.encode_utf16().count() as u32);
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }

    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }

    let code_off = bytes.len() as u32;
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 1);
    push_u16(&mut bytes, 0x000e);

    let class_data_off = bytes.len() as u32;
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 1);
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 0x0009);
    write_uleb128(&mut bytes, code_off);

    let file_size = bytes.len() as u32;
    bytes[0..8].copy_from_slice(b"dex\n035\0");
    put_u32(&mut bytes, 32, file_size);
    put_u32(&mut bytes, 36, DEX_HEADER_SIZE);
    put_u32(&mut bytes, 40, DEX_ENDIAN_CONSTANT);
    put_u32(&mut bytes, 44, 0);
    put_u32(&mut bytes, 48, 0);
    put_u32(&mut bytes, 52, 0);
    put_u32(&mut bytes, 56, strings.len() as u32);
    put_u32(&mut bytes, 60, string_ids_off);
    put_u32(&mut bytes, 64, 3);
    put_u32(&mut bytes, 68, type_ids_off);
    put_u32(&mut bytes, 72, 1);
    put_u32(&mut bytes, 76, proto_ids_off);
    put_u32(&mut bytes, 80, 0);
    put_u32(&mut bytes, 84, 0);
    put_u32(&mut bytes, 88, 1);
    put_u32(&mut bytes, 92, method_ids_off);
    put_u32(&mut bytes, 96, 1);
    put_u32(&mut bytes, 100, class_defs_off);
    put_u32(&mut bytes, 104, file_size - data_off);
    put_u32(&mut bytes, 108, data_off);

    for (index, offset) in string_offsets.iter().enumerate() {
        put_u32(&mut bytes, string_ids_off as usize + index * 4, *offset);
    }

    put_u32(&mut bytes, type_ids_off as usize, 0);
    put_u32(&mut bytes, type_ids_off as usize + 4, 1);
    put_u32(&mut bytes, type_ids_off as usize + 8, 2);

    put_u32(&mut bytes, proto_ids_off as usize, 2);
    put_u32(&mut bytes, proto_ids_off as usize + 4, 2);
    put_u32(&mut bytes, proto_ids_off as usize + 8, 0);

    put_u16(&mut bytes, method_ids_off as usize, 0);
    put_u16(&mut bytes, method_ids_off as usize + 2, 0);
    put_u32(&mut bytes, method_ids_off as usize + 4, 3);

    put_u32(&mut bytes, class_defs_off as usize, 0);
    put_u32(&mut bytes, class_defs_off as usize + 4, 1);
    put_u32(&mut bytes, class_defs_off as usize + 8, 1);
    put_u32(&mut bytes, class_defs_off as usize + 12, 0);
    put_u32(&mut bytes, class_defs_off as usize + 16, 4);
    put_u32(&mut bytes, class_defs_off as usize + 20, 0);
    put_u32(&mut bytes, class_defs_off as usize + 24, class_data_off);
    put_u32(&mut bytes, class_defs_off as usize + 28, 0);

    refresh_integrity(&mut bytes).expect("refresh fixture integrity");
    bytes
}

fn write_uleb128(output: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
