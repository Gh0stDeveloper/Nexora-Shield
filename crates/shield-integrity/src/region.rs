use crate::error::{IntegrityError, Result};
use crate::hash::Sha256Digest;
use nexora_shield_dex::{DexParser, DexValidator};
use serde::{Deserialize, Serialize};

pub const DEFAULT_DEX_CHUNK_BYTES: u32 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityRegion {
    pub label: String,
    pub offset: u32,
    pub length: u32,
    pub digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DexIntegrity {
    pub name: String,
    pub file_size: u64,
    pub file_digest: Sha256Digest,
    pub regions: Vec<IntegrityRegion>,
}

impl DexIntegrity {
    pub fn build(name: impl Into<String>, bytes: &[u8], chunk_bytes: u32) -> Result<Self> {
        let name = name.into();
        if name.is_empty() || chunk_bytes == 0 {
            return Err(IntegrityError::InvalidRegion(
                "DEX name and chunk size must be non-empty/non-zero".into(),
            ));
        }

        let dex = DexParser::parse(bytes)?;
        let _ = DexValidator::validate(&dex)?;
        let header = &dex.header;

        let mut regions = Vec::new();
        push_region(&mut regions, "header", bytes, 0, header.header_size)?;
        push_table_region(
            &mut regions,
            "string_ids",
            bytes,
            header.string_ids_off,
            header.string_ids_size,
            4,
        )?;
        push_table_region(
            &mut regions,
            "type_ids",
            bytes,
            header.type_ids_off,
            header.type_ids_size,
            4,
        )?;
        push_table_region(
            &mut regions,
            "proto_ids",
            bytes,
            header.proto_ids_off,
            header.proto_ids_size,
            12,
        )?;
        push_table_region(
            &mut regions,
            "field_ids",
            bytes,
            header.field_ids_off,
            header.field_ids_size,
            8,
        )?;
        push_table_region(
            &mut regions,
            "method_ids",
            bytes,
            header.method_ids_off,
            header.method_ids_size,
            8,
        )?;
        push_table_region(
            &mut regions,
            "class_defs",
            bytes,
            header.class_defs_off,
            header.class_defs_size,
            32,
        )?;

        if header.data_size != 0 {
            let mut relative = 0_u32;
            let mut chunk_index = 0_u32;
            while relative < header.data_size {
                let remaining = header.data_size - relative;
                let length = remaining.min(chunk_bytes);
                let offset = header
                    .data_off
                    .checked_add(relative)
                    .ok_or_else(|| IntegrityError::InvalidRegion("DEX data offset overflow".into()))?;
                push_region(
                    &mut regions,
                    &format!("data:{chunk_index}"),
                    bytes,
                    offset,
                    length,
                )?;
                relative = relative
                    .checked_add(length)
                    .ok_or_else(|| IntegrityError::InvalidRegion("DEX data chunk overflow".into()))?;
                chunk_index = chunk_index
                    .checked_add(1)
                    .ok_or_else(|| IntegrityError::InvalidRegion("too many DEX chunks".into()))?;
            }
        }

        Ok(Self {
            name,
            file_size: u64::try_from(bytes.len())
                .map_err(|_| IntegrityError::InvalidRegion("DEX size does not fit u64".into()))?,
            file_digest: Sha256Digest::of(bytes),
            regions,
        })
    }

    pub fn verify(&self, bytes: &[u8]) -> Result<Vec<RegionCheck>> {
        let observed_size = u64::try_from(bytes.len())
            .map_err(|_| IntegrityError::InvalidRegion("DEX size does not fit u64".into()))?;
        let mut checks = Vec::with_capacity(self.regions.len() + 1);
        checks.push(RegionCheck {
            label: "file".into(),
            matched: observed_size == self.file_size && Sha256Digest::of(bytes) == self.file_digest,
            expected: self.file_digest,
            observed: Sha256Digest::of(bytes),
        });

        for region in &self.regions {
            let slice = region_slice(bytes, region.offset, region.length)?;
            let observed = Sha256Digest::of(slice);
            checks.push(RegionCheck {
                label: region.label.clone(),
                matched: observed == region.digest,
                expected: region.digest,
                observed,
            });
        }
        Ok(checks)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionCheck {
    pub label: String,
    pub matched: bool,
    pub expected: Sha256Digest,
    pub observed: Sha256Digest,
}

fn push_table_region(
    regions: &mut Vec<IntegrityRegion>,
    label: &str,
    bytes: &[u8],
    offset: u32,
    count: u32,
    item_size: u32,
) -> Result<()> {
    if count == 0 {
        return Ok(());
    }
    let length = count
        .checked_mul(item_size)
        .ok_or_else(|| IntegrityError::InvalidRegion(format!("{label} length overflow")))?;
    push_region(regions, label, bytes, offset, length)
}

fn push_region(
    regions: &mut Vec<IntegrityRegion>,
    label: &str,
    bytes: &[u8],
    offset: u32,
    length: u32,
) -> Result<()> {
    if length == 0 {
        return Ok(());
    }
    let slice = region_slice(bytes, offset, length)?;
    regions.push(IntegrityRegion {
        label: label.to_owned(),
        offset,
        length,
        digest: Sha256Digest::of(slice),
    });
    Ok(())
}

fn region_slice(bytes: &[u8], offset: u32, length: u32) -> Result<&[u8]> {
    let start = usize::try_from(offset)
        .map_err(|_| IntegrityError::InvalidRegion("region offset does not fit usize".into()))?;
    let length = usize::try_from(length)
        .map_err(|_| IntegrityError::InvalidRegion("region length does not fit usize".into()))?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| IntegrityError::InvalidRegion("region end overflow".into()))?;
    bytes.get(start..end).ok_or_else(|| {
        IntegrityError::InvalidRegion(format!(
            "region 0x{offset:x}+{length} extends beyond {} bytes",
            bytes.len()
        ))
    })
}
