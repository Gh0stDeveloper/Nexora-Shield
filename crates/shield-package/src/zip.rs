use crate::error::{PackageError, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const EOCD_MIN_SIZE: usize = 22;
const MAX_ZIP_COMMENT: usize = u16::MAX as usize;
const NORMALIZED_DOS_DATE: u16 = 0x0021;
const NORMALIZED_DOS_TIME: u16 = 0x0000;

/// Automatically removes a partially written archive on any error path.
#[derive(Debug)]
struct IncompleteOutput<'a> {
    path: &'a Path,
    completed: bool,
}

impl Drop for IncompleteOutput<'_> {
    fn drop(&mut self) {
        if !self.completed {
            let _ = std::fs::remove_file(self.path);
        }
    }
}

/// Metadata for one standard (non-ZIP64) ZIP entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    pub name: String,
    pub flags: u16,
    pub compression_method: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub version_made_by: u16,
    pub version_needed: u16,
    pub internal_attributes: u16,
    pub external_attributes: u32,
    pub local_header_offset: u32,
    pub local_extra: Vec<u8>,
    pub central_extra: Vec<u8>,
    pub comment: Vec<u8>,
}

/// Parsed standard ZIP directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipDirectory {
    pub entries: Vec<ZipEntry>,
    pub source_comment_len: u16,
}

/// Result of deterministic archive normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizationSummary {
    pub input_entries: usize,
    pub output_entries: usize,
    pub stripped_signature_entries: Vec<String>,
}

#[derive(Debug, Clone)]
struct EndOfCentralDirectory {
    entries: u16,
    central_size: u32,
    central_offset: u32,
    comment_len: u16,
}

#[derive(Debug, Clone)]
struct CentralRecord {
    entry: ZipEntry,
    name_len: u16,
    extra_len: u16,
    comment_len: u16,
}

/// Parses the standard ZIP32 central directory and validates entry metadata.
///
/// # Errors
///
/// Returns an error for malformed, unsafe, encrypted, ZIP64, multi-disk, or
/// otherwise unsupported archives.
pub fn read_zip_directory(path: &Path) -> Result<ZipDirectory> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    if file_len < EOCD_MIN_SIZE as u64 {
        return Err(PackageError::InvalidZip(
            "file is smaller than an EOCD record".into(),
        ));
    }

    let tail_len = usize::try_from(file_len.min((EOCD_MIN_SIZE + MAX_ZIP_COMMENT) as u64))
        .map_err(|_| PackageError::UnsupportedZip("archive tail does not fit memory".into()))?;
    let tail_start = file_len - tail_len as u64;
    file.seek(SeekFrom::Start(tail_start))?;

    let mut tail = vec![0_u8; tail_len];
    file.read_exact(&mut tail)?;
    let eocd_offset = find_eocd(&tail)
        .ok_or_else(|| PackageError::InvalidZip("end-of-central-directory not found".into()))?;
    let eocd = parse_eocd(&tail[eocd_offset..])?;

    validate_eocd(&eocd, file_len)?;

    file.seek(SeekFrom::Start(u64::from(eocd.central_offset)))?;
    let central_size = usize::try_from(eocd.central_size)
        .map_err(|_| PackageError::UnsupportedZip("central directory is too large".into()))?;
    let mut central = vec![0_u8; central_size];
    file.read_exact(&mut central)?;

    let mut entries = Vec::with_capacity(usize::from(eocd.entries));
    let mut cursor = 0_usize;
    let mut names = BTreeSet::new();

    for _ in 0..eocd.entries {
        let record = parse_central_record(&central[cursor..])?;
        let record_size = 46_usize
            .checked_add(usize::from(record.name_len))
            .and_then(|value| value.checked_add(usize::from(record.extra_len)))
            .and_then(|value| value.checked_add(usize::from(record.comment_len)))
            .ok_or_else(|| PackageError::InvalidZip("central record length overflow".into()))?;

        if !names.insert(record.entry.name.clone()) {
            return Err(PackageError::DuplicateEntry(record.entry.name));
        }

        validate_entry_name(&record.entry.name)?;
        validate_entry_capabilities(&record.entry)?;
        entries.push(record.entry);

        cursor = cursor
            .checked_add(record_size)
            .ok_or_else(|| PackageError::InvalidZip("central directory cursor overflow".into()))?;
        if cursor > central.len() {
            return Err(PackageError::InvalidZip(
                "central directory is truncated".into(),
            ));
        }
    }

    if cursor != central.len() {
        return Err(PackageError::InvalidZip(
            "central directory contains unexpected trailing bytes".into(),
        ));
    }

    populate_local_extra_fields(&mut file, &mut entries)?;

    Ok(ZipDirectory {
        entries,
        source_comment_len: eocd.comment_len,
    })
}

/// Rebuilds a deterministic APK archive while preserving compressed payload bytes.
///
/// # Errors
///
/// Returns an error when the input is malformed/unsupported, the output cannot
/// be written, or standard ZIP32 limits would be exceeded.
pub fn normalize_zip(input: &Path, output: &Path) -> Result<NormalizationSummary> {
    rewrite_stored_entries(input, output, &BTreeMap::new())
}

/// Rebuilds ZIP32 while replacing explicitly named stored entries.
///
/// Only STORE payloads may be replaced; a compressed or absent target is an
/// error. Existing signature metadata is stripped because rewritten content
/// invalidates signatures. Callers must verify the artifact and re-sign it.
///
/// # Errors
///
/// Rejects missing/unsupported target entries, unsafe replacement sizes and
/// invalid ZIP32 inputs. The destination should be a private transaction path.
pub fn rewrite_stored_entries(
    input: &Path,
    output: &Path,
    replacements: &BTreeMap<String, Vec<u8>>,
) -> Result<NormalizationSummary> {
    if input == output {
        return Err(PackageError::InvalidArgument(
            "input and output paths must be different".into(),
        ));
    }

    let directory = read_zip_directory(input)?;
    let input_entries = directory.entries.len();
    let mut entries = directory.entries;
    let mut stripped = Vec::new();

    entries.retain(|entry| {
        if is_legacy_signature_entry(&entry.name) {
            stripped.push(entry.name.clone());
            false
        } else {
            true
        }
    });
    entries.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));

    validate_replacements(&entries, replacements)?;

    let mut source = File::open(input)?;
    // Exclusive creation ensures an existing artifact or symlink is never
    // overwritten, even if a concurrent process races the caller's preflight.
    // The guard is declared BEFORE the file handle: on Windows the handle
    // closes before cleanup attempts to unlink a failed partial archive.
    let mut incomplete = IncompleteOutput { path: output, completed: true };
    let mut destination = File::options().write(true).create_new(true).open(output)?;
    incomplete.completed = false;
    let mut written = Vec::with_capacity(entries.len());

    for mut entry in entries {
        if let Some(bytes) = replacements.get(&entry.name) {
            let size = u32::try_from(bytes.len()).map_err(|_| {
                PackageError::UnsupportedZip(format!(
                    "replacement '{}' exceeds ZIP32 size limits",
                    entry.name
                ))
            })?;
            entry.crc32 = crc32_ieee(bytes);
            entry.compressed_size = size;
            entry.uncompressed_size = size;
        }

        let output_offset = destination.stream_position()?;
        let output_offset = u32::try_from(output_offset).map_err(|_| {
            PackageError::UnsupportedZip("normalized APK exceeds standard ZIP offset limits".into())
        })?;

        let local_extra = filter_extra_fields(&entry.local_extra)?;
        write_local_header(&mut destination, &entry, &local_extra)?;
        destination.write_all(entry.name.as_bytes())?;
        destination.write_all(&local_extra)?;

        if let Some(bytes) = replacements.get(&entry.name) {
            destination.write_all(bytes)?;
        } else {
            let data_offset = local_data_offset(&mut source, &entry)?;
            source.seek(SeekFrom::Start(data_offset))?;
            let mut limited = (&mut source).take(u64::from(entry.compressed_size));
            let copied = std::io::copy(&mut limited, &mut destination)?;
            if copied != u64::from(entry.compressed_size) {
                return Err(PackageError::InvalidZip(format!(
                    "compressed payload for '{}' is truncated",
                    entry.name
                )));
            }
        }

        let mut updated = entry;
        updated.local_header_offset = output_offset;
        updated.local_extra = local_extra;
        updated.central_extra = filter_extra_fields(&updated.central_extra)?;
        updated.flags &= !0x0008;
        written.push(updated);
    }

    let central_offset = destination.stream_position()?;
    let central_offset_u32 = u32::try_from(central_offset).map_err(|_| {
        PackageError::UnsupportedZip("normalized APK central directory exceeds ZIP32".into())
    })?;

    for entry in &written {
        write_central_header(&mut destination, entry)?;
    }

    let central_end = destination.stream_position()?;
    let central_size = central_end
        .checked_sub(central_offset)
        .ok_or_else(|| PackageError::InvalidZip("central directory position underflow".into()))?;
    let central_size_u32 = u32::try_from(central_size).map_err(|_| {
        PackageError::UnsupportedZip("normalized APK central directory is too large".into())
    })?;
    let entry_count = u16::try_from(written.len()).map_err(|_| {
        PackageError::UnsupportedZip("normalized APK has more than 65535 entries".into())
    })?;

    write_u32(&mut destination, EOCD_SIGNATURE)?;
    write_u16(&mut destination, 0)?;
    write_u16(&mut destination, 0)?;
    write_u16(&mut destination, entry_count)?;
    write_u16(&mut destination, entry_count)?;
    write_u32(&mut destination, central_size_u32)?;
    write_u32(&mut destination, central_offset_u32)?;
    write_u16(&mut destination, 0)?;
    destination.flush()?;
    destination.sync_all()?;
    incomplete.completed = true;

    Ok(NormalizationSummary {
        input_entries,
        output_entries: written.len(),
        stripped_signature_entries: stripped,
    })
}

fn validate_replacements(
    entries: &[ZipEntry],
    replacements: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    // Each requested target must exist and use ZIP STORE.
    for name in replacements.keys() {
        let entry = entries
            .iter()
            .find(|entry| entry.name == *name)
            .ok_or_else(|| {
                PackageError::InvalidArgument(format!("replacement target '{name}' is absent"))
            })?;
        if entry.compression_method != 0 {
            return Err(PackageError::UnsupportedZip(format!(
                "replacement target '{name}' must use ZIP STORE"
            )));
        }
    }
    Ok(())
}

/// Confirms that normalization preserved non-signature payload identities.
///
/// # Errors
///
/// Returns an error when either archive is invalid or the entry identity,
/// content CRC, size, or compression method changed.
pub fn verify_normalized_equivalence(input: &Path, normalized: &Path) -> Result<()> {
    let original = read_zip_directory(input)?;
    let result = read_zip_directory(normalized)?;

    let expected = content_identity(&original.entries, true);
    let actual = content_identity(&result.entries, false);

    if expected != actual {
        return Err(PackageError::VerificationFailed(
            "normalized archive changed entry identity, CRC, size or compression method".into(),
        ));
    }

    Ok(())
}

#[must_use]
pub fn is_legacy_signature_entry(name: &str) -> bool {
    let uppercase = name.to_ascii_uppercase();
    let Some(rest) = uppercase.strip_prefix("META-INF/") else {
        return false;
    };

    let signature_extension = Path::new(rest)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| matches!(extension, "SF" | "RSA" | "DSA" | "EC"));

    rest == "MANIFEST.MF" || rest.starts_with("SIG-") || signature_extension
}

/// Reads a bounded STORE-method entry for metadata inspection.
///
/// # Errors
///
/// Returns an error when local ZIP metadata is inconsistent or I/O fails.
pub fn read_stored_entry(
    path: &Path,
    entry: &ZipEntry,
    max_size: usize,
) -> Result<Option<Vec<u8>>> {
    if entry.compression_method != 0 {
        return Ok(None);
    }

    let length = usize::try_from(entry.uncompressed_size)
        .map_err(|_| PackageError::UnsupportedZip("entry is too large to inspect".into()))?;
    if length > max_size {
        return Ok(None);
    }

    let mut file = File::open(path)?;
    let data_offset = local_data_offset(&mut file, entry)?;
    file.seek(SeekFrom::Start(data_offset))?;
    let mut data = vec![0_u8; length];
    file.read_exact(&mut data)?;
    Ok(Some(data))
}

/// Standard IEEE CRC-32 for ZIP entry integrity; not a cryptographic hash.
#[must_use]
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320_u32 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

fn content_identity(entries: &[ZipEntry], ignore_signatures: bool) -> Vec<(String, u32, u32, u16)> {
    let mut identity = entries
        .iter()
        .filter(|entry| !ignore_signatures || !is_legacy_signature_entry(&entry.name))
        .map(|entry| {
            (
                entry.name.clone(),
                entry.crc32,
                entry.uncompressed_size,
                entry.compression_method,
            )
        })
        .collect::<Vec<_>>();
    identity.sort_by(|left, right| left.0.cmp(&right.0));
    identity
}

fn find_eocd(tail: &[u8]) -> Option<usize> {
    if tail.len() < EOCD_MIN_SIZE {
        return None;
    }

    (0..=tail.len() - EOCD_MIN_SIZE)
        .rev()
        .find(|&index| read_u32_at(tail, index).ok() == Some(EOCD_SIGNATURE))
}

fn parse_eocd(data: &[u8]) -> Result<EndOfCentralDirectory> {
    ensure_len(data, EOCD_MIN_SIZE, "EOCD")?;
    if read_u32_at(data, 0)? != EOCD_SIGNATURE {
        return Err(PackageError::InvalidZip("invalid EOCD signature".into()));
    }

    let disk = read_u16_at(data, 4)?;
    let central_disk = read_u16_at(data, 6)?;
    let disk_entries = read_u16_at(data, 8)?;
    let total_entries = read_u16_at(data, 10)?;
    let central_size = read_u32_at(data, 12)?;
    let central_offset = read_u32_at(data, 16)?;
    let comment_len = read_u16_at(data, 20)?;

    if disk != 0 || central_disk != 0 || disk_entries != total_entries {
        return Err(PackageError::UnsupportedZip(
            "multi-disk ZIP archives are not supported".into(),
        ));
    }
    if total_entries == u16::MAX || central_size == u32::MAX || central_offset == u32::MAX {
        return Err(PackageError::UnsupportedZip(
            "ZIP64 APKs are deferred beyond Phase A".into(),
        ));
    }

    let expected = EOCD_MIN_SIZE
        .checked_add(usize::from(comment_len))
        .ok_or_else(|| PackageError::InvalidZip("EOCD comment length overflow".into()))?;
    ensure_len(data, expected, "EOCD comment")?;

    Ok(EndOfCentralDirectory {
        entries: total_entries,
        central_size,
        central_offset,
        comment_len,
    })
}

fn validate_eocd(eocd: &EndOfCentralDirectory, file_len: u64) -> Result<()> {
    let central_end = u64::from(eocd.central_offset)
        .checked_add(u64::from(eocd.central_size))
        .ok_or_else(|| PackageError::InvalidZip("central directory overflow".into()))?;
    if central_end > file_len {
        return Err(PackageError::InvalidZip(
            "central directory extends beyond end of file".into(),
        ));
    }
    Ok(())
}

fn parse_central_record(data: &[u8]) -> Result<CentralRecord> {
    ensure_len(data, 46, "central directory record")?;
    if read_u32_at(data, 0)? != CENTRAL_SIGNATURE {
        return Err(PackageError::InvalidZip(
            "invalid central-directory entry signature".into(),
        ));
    }

    let version_made_by = read_u16_at(data, 4)?;
    let version_needed = read_u16_at(data, 6)?;
    let flags = read_u16_at(data, 8)?;
    let compression_method = read_u16_at(data, 10)?;
    let crc32 = read_u32_at(data, 16)?;
    let compressed_size = read_u32_at(data, 20)?;
    let uncompressed_size = read_u32_at(data, 24)?;
    let name_len = read_u16_at(data, 28)?;
    let extra_len = read_u16_at(data, 30)?;
    let comment_len = read_u16_at(data, 32)?;
    let disk_start = read_u16_at(data, 34)?;
    let internal_attributes = read_u16_at(data, 36)?;
    let external_attributes = read_u32_at(data, 38)?;
    let local_header_offset = read_u32_at(data, 42)?;

    if disk_start != 0 {
        return Err(PackageError::UnsupportedZip(
            "entry references a non-zero ZIP disk".into(),
        ));
    }
    if compressed_size == u32::MAX
        || uncompressed_size == u32::MAX
        || local_header_offset == u32::MAX
    {
        return Err(PackageError::UnsupportedZip(
            "ZIP64 entry fields are not supported in Phase A".into(),
        ));
    }

    let name_start = 46_usize;
    let extra_start = name_start + usize::from(name_len);
    let comment_start = extra_start + usize::from(extra_len);
    let end = comment_start + usize::from(comment_len);
    ensure_len(data, end, "central directory entry variable fields")?;

    let name_bytes = &data[name_start..extra_start];
    let name = std::str::from_utf8(name_bytes)
        .map_err(|_| PackageError::InvalidEntryName("<non-UTF8>".into()))?
        .to_owned();

    Ok(CentralRecord {
        entry: ZipEntry {
            name,
            flags,
            compression_method,
            crc32,
            compressed_size,
            uncompressed_size,
            version_made_by,
            version_needed,
            internal_attributes,
            external_attributes,
            local_header_offset,
            local_extra: Vec::new(),
            central_extra: data[extra_start..comment_start].to_vec(),
            comment: data[comment_start..end].to_vec(),
        },
        name_len,
        extra_len,
        comment_len,
    })
}

fn populate_local_extra_fields(file: &mut File, entries: &mut [ZipEntry]) -> Result<()> {
    for entry in entries {
        file.seek(SeekFrom::Start(u64::from(entry.local_header_offset)))?;
        let mut fixed = [0_u8; 30];
        file.read_exact(&mut fixed)?;

        if read_u32_at(&fixed, 0)? != LOCAL_SIGNATURE {
            return Err(PackageError::InvalidZip(format!(
                "local header for '{}' has an invalid signature",
                entry.name
            )));
        }

        let local_name_len = read_u16_at(&fixed, 26)?;
        let local_extra_len = read_u16_at(&fixed, 28)?;
        let mut local_name = vec![0_u8; usize::from(local_name_len)];
        file.read_exact(&mut local_name)?;

        if local_name != entry.name.as_bytes() {
            return Err(PackageError::InvalidZip(format!(
                "central/local name mismatch for '{}'",
                entry.name
            )));
        }

        let mut extra = vec![0_u8; usize::from(local_extra_len)];
        file.read_exact(&mut extra)?;
        entry.local_extra = extra;
    }
    Ok(())
}

fn validate_entry_capabilities(entry: &ZipEntry) -> Result<()> {
    if entry.flags & 0x0001 != 0 {
        return Err(PackageError::UnsupportedZip(format!(
            "encrypted ZIP entry '{}' is not supported",
            entry.name
        )));
    }

    if !matches!(entry.compression_method, 0 | 8) {
        return Err(PackageError::UnsupportedZip(format!(
            "compression method {} for '{}' is not supported",
            entry.compression_method, entry.name
        )));
    }

    Ok(())
}

fn validate_entry_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.starts_with('/')
        || name.starts_with('\\')
        || name.contains('\\')
        || name.contains('\0')
        || name.split('/').any(|component| component == "..")
    {
        return Err(PackageError::InvalidEntryName(name.to_owned()));
    }
    Ok(())
}

fn local_data_offset(file: &mut File, entry: &ZipEntry) -> Result<u64> {
    file.seek(SeekFrom::Start(u64::from(entry.local_header_offset)))?;
    let mut fixed = [0_u8; 30];
    file.read_exact(&mut fixed)?;

    if read_u32_at(&fixed, 0)? != LOCAL_SIGNATURE {
        return Err(PackageError::InvalidZip(format!(
            "local header for '{}' is invalid",
            entry.name
        )));
    }

    let name_len = u64::from(read_u16_at(&fixed, 26)?);
    let extra_len = u64::from(read_u16_at(&fixed, 28)?);
    u64::from(entry.local_header_offset)
        .checked_add(30)
        .and_then(|value| value.checked_add(name_len))
        .and_then(|value| value.checked_add(extra_len))
        .ok_or_else(|| PackageError::InvalidZip("local data offset overflow".into()))
}

fn filter_extra_fields(extra: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = 0_usize;
    let mut output = Vec::with_capacity(extra.len());

    while cursor < extra.len() {
        let remaining = &extra[cursor..];

        // Android Zipflinger may use raw zero bytes in the local extra area
        // purely as alignment padding. They are not ZIP extra-field TLVs.
        // Accept and strip only an all-zero suffix; malformed non-zero
        // trailing bytes remain a hard error.
        if remaining.iter().all(|byte| *byte == 0) {
            break;
        }

        ensure_len(remaining, 4, "ZIP extra field header")?;
        let identifier = read_u16_at(extra, cursor)?;
        let size = usize::from(read_u16_at(extra, cursor + 2)?);
        let end = cursor
            .checked_add(4)
            .and_then(|value| value.checked_add(size))
            .ok_or_else(|| PackageError::InvalidZip("ZIP extra field length overflow".into()))?;
        ensure_len(extra, end, "ZIP extra field")?;

        // Extended timestamps, NTFS timestamps and Android zipalign padding are regenerated/removed.
        if !matches!(identifier, 0x5455 | 0x000a | 0xd935) {
            output.extend_from_slice(&extra[cursor..end]);
        }
        cursor = end;
    }

    Ok(output)
}

fn write_local_header(writer: &mut File, entry: &ZipEntry, extra: &[u8]) -> Result<()> {
    let name_len = u16::try_from(entry.name.len())
        .map_err(|_| PackageError::UnsupportedZip("entry name is too long".into()))?;
    let extra_len = u16::try_from(extra.len())
        .map_err(|_| PackageError::UnsupportedZip("local extra field is too long".into()))?;

    write_u32(writer, LOCAL_SIGNATURE)?;
    write_u16(writer, entry.version_needed.max(20))?;
    write_u16(writer, entry.flags & !0x0008)?;
    write_u16(writer, entry.compression_method)?;
    write_u16(writer, NORMALIZED_DOS_TIME)?;
    write_u16(writer, NORMALIZED_DOS_DATE)?;
    write_u32(writer, entry.crc32)?;
    write_u32(writer, entry.compressed_size)?;
    write_u32(writer, entry.uncompressed_size)?;
    write_u16(writer, name_len)?;
    write_u16(writer, extra_len)?;
    Ok(())
}

fn write_central_header(writer: &mut File, entry: &ZipEntry) -> Result<()> {
    let name_len = u16::try_from(entry.name.len())
        .map_err(|_| PackageError::UnsupportedZip("entry name is too long".into()))?;
    let extra_len = u16::try_from(entry.central_extra.len())
        .map_err(|_| PackageError::UnsupportedZip("central extra field is too long".into()))?;
    let comment_len = u16::try_from(entry.comment.len())
        .map_err(|_| PackageError::UnsupportedZip("entry comment is too long".into()))?;

    write_u32(writer, CENTRAL_SIGNATURE)?;
    write_u16(writer, entry.version_made_by)?;
    write_u16(writer, entry.version_needed.max(20))?;
    write_u16(writer, entry.flags & !0x0008)?;
    write_u16(writer, entry.compression_method)?;
    write_u16(writer, NORMALIZED_DOS_TIME)?;
    write_u16(writer, NORMALIZED_DOS_DATE)?;
    write_u32(writer, entry.crc32)?;
    write_u32(writer, entry.compressed_size)?;
    write_u32(writer, entry.uncompressed_size)?;
    write_u16(writer, name_len)?;
    write_u16(writer, extra_len)?;
    write_u16(writer, comment_len)?;
    write_u16(writer, 0)?;
    write_u16(writer, entry.internal_attributes)?;
    write_u32(writer, entry.external_attributes)?;
    write_u32(writer, entry.local_header_offset)?;
    writer.write_all(entry.name.as_bytes())?;
    writer.write_all(&entry.central_extra)?;
    writer.write_all(&entry.comment)?;
    Ok(())
}

fn ensure_len(data: &[u8], required: usize, label: &str) -> Result<()> {
    if data.len() < required {
        return Err(PackageError::InvalidZip(format!("{label} is truncated")));
    }
    Ok(())
}

fn read_u16_at(data: &[u8], offset: usize) -> Result<u16> {
    ensure_len(data, offset.saturating_add(2), "u16 field")?;
    Ok(u16::from_le_bytes([data[offset], data[offset + 1]]))
}

fn read_u32_at(data: &[u8], offset: usize) -> Result<u32> {
    ensure_len(data, offset.saturating_add(4), "u32 field")?;
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

fn write_u16(writer: &mut File, value: u16) -> Result<()> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

fn write_u32(writer: &mut File, value: u32) -> Result<()> {
    writer.write_all(&value.to_le_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{filter_extra_fields, is_legacy_signature_entry, validate_entry_name};

    #[test]
    fn signature_entries_are_detected_case_insensitively() {
        assert!(is_legacy_signature_entry("META-INF/MANIFEST.MF"));
        assert!(is_legacy_signature_entry("META-INF/CERT.RSA"));
        assert!(is_legacy_signature_entry("meta-inf/cert.sf"));
        assert!(!is_legacy_signature_entry(
            "META-INF/services/example.Service"
        ));
    }

    #[test]
    fn unsafe_paths_are_rejected() {
        assert!(validate_entry_name("../classes.dex").is_err());
        assert!(validate_entry_name("/classes.dex").is_err());
        assert!(validate_entry_name("dir\\classes.dex").is_err());
        assert!(validate_entry_name("classes.dex").is_ok());
    }

    #[test]
    fn raw_zero_alignment_padding_is_accepted_and_removed() -> super::Result<()> {
        assert_eq!(filter_extra_fields(&[0_u8; 1])?, Vec::<u8>::new());
        assert_eq!(filter_extra_fields(&[0_u8; 7])?, Vec::<u8>::new());
        Ok(())
    }

    #[test]
    fn structured_fields_can_be_followed_by_raw_zero_padding() -> super::Result<()> {
        let extra = [
            0x34, 0x12, // id 0x1234
            0x02, 0x00, // payload size 2
            0xaa, 0xbb, // payload
            0x00, 0x00, 0x00, // Zipflinger alignment padding
        ];
        assert_eq!(
            filter_extra_fields(&extra)?,
            vec![0x34, 0x12, 0x02, 0x00, 0xaa, 0xbb]
        );
        Ok(())
    }

    #[test]
    fn non_zero_truncated_extra_data_is_rejected() {
        assert!(filter_extra_fields(&[0x01, 0x02, 0x03]).is_err());
    }
}
