// Synthetic DEX fixture, not an Android installable application.
use nexora_shield_dex::{refresh_integrity, DEX_ENDIAN_CONSTANT, DEX_HEADER_SIZE};

pub fn build_test_dex(class_descriptor: &str, method_name: &str) -> Vec<u8> {
    build_test_dex_with_superclass(class_descriptor, method_name, "Ljava/lang/Object;")
}

fn build_test_dex_with_superclass(
    class_descriptor: &str,
    method_name: &str,
    superclass: &str,
) -> Vec<u8> {
    let strings = [class_descriptor, superclass, "V", method_name, "A.java"];

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
