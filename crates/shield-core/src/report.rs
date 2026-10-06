use crate::pipeline::{PipelineResult, PipelineStage};
use nexora_shield_package::ApkInspection;
use std::fs;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicBuildReport {
    pub build_id: String,
    pub schema_version: u32,
    pub profile: String,
    pub input_sha256: String,
    pub output_sha256: String,
    pub input_size: u64,
    pub output_size: u64,
    pub entry_count: usize,
    pub dex_count: usize,
    pub manifest_format: String,
    pub aligned: bool,
    pub signed: bool,
    pub stripped_signature_entries: usize,
    pub stages: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateBuildReport {
    pub build_id: String,
    pub input_path: String,
    pub output_path: String,
    pub created_unix_ms: u128,
    pub dex_files: Vec<String>,
    pub stripped_signature_entries: Vec<String>,
    pub stages: Vec<String>,
}

impl PublicBuildReport {
    #[must_use]
    pub fn from_pipeline(result: &PipelineResult) -> Self {
        Self {
            build_id: result.plan.build_id.clone(),
            schema_version: result.plan.schema_version,
            profile: result.plan.profile.to_string(),
            input_sha256: result.input_inspection.sha256.clone(),
            output_sha256: result.output_inspection.sha256.clone(),
            input_size: result.input_inspection.file_size,
            output_size: result.output_inspection.file_size,
            entry_count: result.output_inspection.entry_count,
            dex_count: result.output_inspection.dex_files.len(),
            manifest_format: result.output_inspection.manifest.format.as_str().to_owned(),
            aligned: result.aligned,
            signed: result.signed,
            stripped_signature_entries: result.normalization.stripped_signature_entries.len(),
            stages: stage_names(&result.stages),
        }
    }

    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"build_id\": \"{}\",\n",
                "  \"schema_version\": {},\n",
                "  \"profile\": \"{}\",\n",
                "  \"input_sha256\": \"{}\",\n",
                "  \"output_sha256\": \"{}\",\n",
                "  \"input_size\": {},\n",
                "  \"output_size\": {},\n",
                "  \"entry_count\": {},\n",
                "  \"dex_count\": {},\n",
                "  \"manifest_format\": \"{}\",\n",
                "  \"aligned\": {},\n",
                "  \"signed\": {},\n",
                "  \"stripped_signature_entries\": {},\n",
                "  \"stages\": {}\n",
                "}}\n"
            ),
            json_escape(&self.build_id),
            self.schema_version,
            json_escape(&self.profile),
            json_escape(&self.input_sha256),
            json_escape(&self.output_sha256),
            self.input_size,
            self.output_size,
            self.entry_count,
            self.dex_count,
            json_escape(&self.manifest_format),
            self.aligned,
            self.signed,
            self.stripped_signature_entries,
            json_string_array(&self.stages)
        )
    }
}

impl PrivateBuildReport {
    #[must_use]
    pub fn from_pipeline(result: &PipelineResult) -> Self {
        Self {
            build_id: result.plan.build_id.clone(),
            input_path: result.plan.input.display().to_string(),
            output_path: result.plan.output.display().to_string(),
            created_unix_ms: result.plan.created_unix_ms,
            dex_files: result
                .output_inspection
                .dex_files
                .iter()
                .map(|dex| dex.name.clone())
                .collect(),
            stripped_signature_entries: result
                .normalization
                .stripped_signature_entries
                .clone(),
            stages: stage_names(&result.stages),
        }
    }

    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"build_id\": \"{}\",\n",
                "  \"input_path\": \"{}\",\n",
                "  \"output_path\": \"{}\",\n",
                "  \"created_unix_ms\": {},\n",
                "  \"dex_files\": {},\n",
                "  \"stripped_signature_entries\": {},\n",
                "  \"stages\": {}\n",
                "}}\n"
            ),
            json_escape(&self.build_id),
            json_escape(&self.input_path),
            json_escape(&self.output_path),
            self.created_unix_ms,
            json_string_array(&self.dex_files),
            json_string_array(&self.stripped_signature_entries),
            json_string_array(&self.stages)
        )
    }
}

#[must_use]
pub fn apk_inspection_json(inspection: &ApkInspection) -> String {
    let dex_names = inspection
        .dex_files
        .iter()
        .map(|dex| dex.name.clone())
        .collect::<Vec<_>>();
    let manifest_sha = inspection
        .manifest
        .content_sha256
        .as_ref()
        .map_or_else(|| "null".to_owned(), |value| format!("\\\"{}\\\"", json_escape(value)));

    format!(
        concat!(
            "{{\n",
            "  \"sha256\": \"{}\",\n",
            "  \"file_size\": {},\n",
            "  \"entry_count\": {},\n",
            "  \"manifest\": {{\n",
            "    \"format\": \"{}\",\n",
            "    \"compression_method\": {},\n",
            "    \"compressed_size\": {},\n",
            "    \"uncompressed_size\": {},\n",
            "    \"crc32\": {},\n",
            "    \"content_sha256\": {}\n",
            "  }},\n",
            "  \"dex_files\": {},\n",
            "  \"dex_sequence_contiguous\": {},\n",
            "  \"legacy_signature_entries\": {}\n",
            "}}\n"
        ),
        json_escape(&inspection.sha256),
        inspection.file_size,
        inspection.entry_count,
        inspection.manifest.format.as_str(),
        inspection.manifest.compression_method,
        inspection.manifest.compressed_size,
        inspection.manifest.uncompressed_size,
        inspection.manifest.crc32,
        manifest_sha,
        json_string_array(&dex_names),
        inspection.dex_sequence_contiguous,
        json_string_array(&inspection.legacy_signature_entries)
    )
}

pub fn write_report_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temporary = path.with_extension("nexora-shield.tmp");
    {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(content.as_bytes())?;
        file.flush()?;
        file.sync_all()?;
    }

    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temporary, path)?;
    Ok(())
}

fn stage_names(stages: &[PipelineStage]) -> Vec<String> {
    stages.iter().map(|stage| stage.as_str().to_owned()).collect()
}

fn json_string_array(values: &[String]) -> String {
    let body = values
        .iter()
        .map(|value| format!("\\\"{}\\\"", json_escape(value)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{body}]")
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", u32::from(character)));
            }
            character => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::json_escape;

    #[test]
    fn json_escape_covers_control_characters() {
        assert_eq!(json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }
}
