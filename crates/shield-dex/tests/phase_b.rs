#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use nexora_shield_dex::{
    refresh_integrity, ControlFlowGraph, DexInput, DexParser, DexRewriteVerifier, DexValidator,
    DexWriter, IrMethod, ReferenceKind,
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
    let selection =
        SelectorResolver::resolve(&dex, std::slice::from_ref(&selector)).expect("selection");
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

#[test]
fn o13_rewrite_audit_proves_only_declared_bytes_changed() {
    let bytes = build_test_dex("Lcom/test/A;", "run");
    let original = DexParser::parse(&bytes).expect("original DEX");
    let transformed = RenamePass::apply(&original, &RenameConfig::default())
        .expect("fixed-layout rename");
    let renamed = DexParser::parse(&transformed.bytes).expect("renamed DEX");
    let (final_bytes, metadata) = MetadataReducer::strip_debug_metadata(&renamed)
        .expect("real metadata removal");
    let audit = DexRewriteVerifier::verify(
        &original,
        &final_bytes,
        Some(&transformed.report),
        Some(&metadata),
    ).expect("every changed byte accounted for");
    assert!(audit.changed_symbol_strings > 0);
    assert_eq!(audit.source_files_removed, 1);
    assert_eq!(audit.preserved_code_items, 1);
}

#[test]
fn o13_symbol_rename_preserves_const_string_literals() {
    let bytes = build_test_dex("Lcom/test/A;", "run");
    let mut parsed = DexParser::parse(&bytes).expect("parse DEX");
    let name_index = parsed.methods[0].name_idx;
    let code = parsed.code_items.values_mut().next().expect("test code");
    code.instructions[0].reference = Some((ReferenceKind::String, name_index));
    let transformed = RenamePass::apply(&parsed, &RenameConfig {
        rename_classes: false,
        rename_methods: true,
        rename_fields: false,
        ..RenameConfig::default()
    }).expect("conservatively retain runtime literal");
    assert!(transformed.report.records.is_empty());
    assert!(transformed.report.skipped_protected.contains(&name_index));
    assert_eq!(transformed.bytes, bytes);
}

#[test]
fn o13_rewrite_audit_rejects_unreported_executable_mutation() {
    let bytes = build_test_dex("Lcom/test/A;", "run");
    let original = DexParser::parse(&bytes).expect("original DEX");
    let code_offset = usize::try_from(
        original.code_items.values().next().expect("test method").offset,
    ).expect("host offset");
    let mut corrupted = bytes;
    corrupted[code_offset + 16] = 0; // Replace return-void with NOP.
    refresh_integrity(&mut corrupted).expect("refresh tampered DEX checksum");
    assert!(DexRewriteVerifier::verify(&original, &corrupted, None, None).is_err());
}

#[test]
fn o13_multidex_refuses_unsafe_cross_unit_renames_but_allows_metadata() {
    let primary = build_test_dex("Lcom/test/Owner;", "run");
    let secondary = build_test_dex_with_superclass(
        "Lcom/test/Other;",
        "go",
        "Lcom/test/Owner;",
    );
    let set = MultiDexSet::parse(vec![
        DexInput {
            name: "classes.dex".into(),
            bytes: primary,
        },
        DexInput {
            name: "classes2.dex".into(),
            bytes: secondary,
        },
    ]).expect("valid cross-unit link");
    let rejected = set.rewrite(&MultiDexRewriteConfig {
        rename: Some(RenameConfig::default()),
        strip_metadata: true,
        ..MultiDexRewriteConfig::default()
    });
    assert!(rejected.expect_err("unsafe remapping must be rejected")
        .to_string().contains("cross-DEX symbol references"));
    let metadata_only = set.rewrite(&MultiDexRewriteConfig {
        rename: None,
        strip_metadata: true,
        ..MultiDexRewriteConfig::default()
    }).expect("metadata-only transformation preserves link");
    assert_eq!(metadata_only.len(), 2);
    assert!(metadata_only.iter().all(|item| item.audit.source_files_removed == 1));
}

#[test]
fn multidex_parser_rejects_duplicate_class_ownership() {
    let primary = build_test_dex("Lcom/test/A;", "run");
    let err = MultiDexSet::parse(vec![
        DexInput {
            name: "classes.dex".into(),
            bytes: primary.clone(),
        },
        DexInput {
            name: "classes2.dex".into(),
            bytes: primary,
        },
    ])
    .expect_err("two canonical DEX units cannot own the same class");
    assert!(err.to_string().contains("duplicate class definition"));
}

#[test]
fn multidex_parser_rejects_gaps_and_noncanonical_dex_names() {
    let first = build_test_dex("Lcom/test/A;", "run");
    let other = build_test_dex("Lcom/test/B;", "go");
    let missing_second = MultiDexSet::parse(vec![
        DexInput {
            name: "classes.dex".into(),
            bytes: first.clone(),
        },
        DexInput {
            name: "classes3.dex".into(),
            bytes: other.clone(),
        },
    ]);
    assert!(missing_second.is_err());
    let leading_zero = MultiDexSet::parse(vec![
        DexInput {
            name: "classes.dex".into(),
            bytes: first,
        },
        DexInput {
            name: "classes02.dex".into(),
            bytes: other,
        },
    ]);
    assert!(leading_zero.is_err());
}

#[test]
fn selector_resolver_revalidates_public_fields_and_rule_limits() {
    let bytes = build_test_dex("Lcom/test/A;", "run");
    let dex = DexParser::parse(&bytes).expect("parse synthetic DEX");
    let malformed = Selector {
        kind: SelectorKind::Method,
        class_pattern: "Lcom/test/A;".into(),
        member_pattern: None,
    };
    assert!(SelectorResolver::resolve(&dex, &[malformed]).is_err());
    let control_chars = Selector {
        kind: SelectorKind::Class,
        class_pattern: "Lcom/test/\0;".into(),
        member_pattern: None,
    };
    assert!(SelectorResolver::resolve(&dex, &[control_chars]).is_err());
    let many = vec![
        Selector {
            kind: SelectorKind::Class,
            class_pattern: "Lcom/test/*;".into(),
            member_pattern: None,
        };
        129
    ];
    assert!(SelectorResolver::resolve(&dex, &many).is_err());
}

fn build_test_dex(class_descriptor: &str, method_name: &str) -> Vec<u8> {
    build_test_dex_with_superclass(class_descriptor, method_name, "Ljava/lang/Object;")
}

fn build_test_dex_with_superclass(
    class_descriptor: &str,
    method_name: &str,
    superclass: &str,
) -> Vec<u8> {
    let strings = [
        class_descriptor,
        superclass,
        "V",
        method_name,
        "A.java",
    ];

    let string_ids_off = DEX_HEADER_SIZE;
    let type_ids_off = string_ids_off + len_u32(strings.len()) * 4;
    let proto_ids_off = type_ids_off + 3 * 4;
    let method_ids_off = proto_ids_off + 12;
    let class_defs_off = method_ids_off + 8;
    let data_off = class_defs_off + 32;

    let mut bytes = vec![0_u8; data_off as usize];
    let mut string_offsets = Vec::with_capacity(strings.len());

    for value in strings {
        string_offsets.push(len_u32(bytes.len()));
        write_uleb128(&mut bytes, len_u32(value.encode_utf16().count()));
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }

    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }

    let code_off = len_u32(bytes.len());
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 1);
    push_u16(&mut bytes, 0x000e);

    let class_data_off = len_u32(bytes.len());
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 1);
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 0);
    write_uleb128(&mut bytes, 0x0009);
    write_uleb128(&mut bytes, code_off);

    let file_size = len_u32(bytes.len());
    bytes[0..8].copy_from_slice(b"dex\n035\0");
    put_u32(&mut bytes, 32, file_size);
    put_u32(&mut bytes, 36, DEX_HEADER_SIZE);
    put_u32(&mut bytes, 40, DEX_ENDIAN_CONSTANT);
    put_u32(&mut bytes, 44, 0);
    put_u32(&mut bytes, 48, 0);
    put_u32(&mut bytes, 52, 0);
    put_u32(&mut bytes, 56, len_u32(strings.len()));
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

fn len_u32(value: usize) -> u32 {
    u32::try_from(value).expect("fixture length fits u32")
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
