//! Build-bound, encrypted retrace maps. No plaintext sidecar is ever emitted.
//!
//! The existing XChaCha20-Poly1305 container authenticates the build identity,
//! opaque item ID and plaintext length. Secrets are never put inside the APK.
use crate::container::{open, seal, ContainerKind};
use crate::error::{DataProtectionError, Result};
use crate::key::KeySchedule;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use zeroize::Zeroizing;

pub const RETRACE_SCHEMA: u32 = 1;
pub const MAX_RETRACE_RECORDS: usize = 200_000;
pub const MAX_RETRACE_PLAINTEXT: usize = 32 * 1024 * 1024;
const RETRACE_DOMAIN: &str = "nexora-shield:o1.3:retrace:v1:";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetraceRecord {
    pub dex_name: String,
    pub string_idx: u32,
    pub original: String,
    pub obfuscated: String,
    pub symbols: Vec<String>,
}

impl fmt::Debug for RetraceRecord {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("RetraceRecord")
            .field("dex_name", &self.dex_name)
            .field("string_idx", &self.string_idx)
            .field("names", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetraceMap {
    pub schema: u32,
    pub build_id: String,
    pub apk_sha256: String,
    pub records: Vec<RetraceRecord>,
}

impl fmt::Debug for RetraceMap {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("RetraceMap")
            .field("schema", &self.schema)
            .field("record_count", &self.records.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

impl RetraceMap {
    pub fn new(
        schedule: &KeySchedule,
        apk_sha256: impl Into<String>,
        records: Vec<RetraceRecord>,
    ) -> Result<Self> {
        let result = Self {
            schema: RETRACE_SCHEMA,
            build_id: schedule.identity().build_id.clone(),
            apk_sha256: apk_sha256.into(),
            records,
        };
        result.validate(schedule)?;
        Ok(result)
    }

    fn validate(&self, schedule: &KeySchedule) -> Result<()> {
        if self.schema != RETRACE_SCHEMA
            || self.build_id != schedule.identity().build_id
            || self.apk_sha256.len() != 64
            || !self.apk_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(DataProtectionError::Metadata(
                "retrace schema, build identity or APK hash mismatch".into(),
            ));
        }
        if self.records.is_empty() || self.records.len() > MAX_RETRACE_RECORDS {
            return Err(DataProtectionError::Metadata(
                "retrace record count outside supported limits".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        for record in &self.records {
            if !canonical_dex_name(&record.dex_name)
                || record.original.is_empty()
                || record.obfuscated.is_empty()
                || record.original == record.obfuscated
                || record.symbols.is_empty()
                || !seen.insert((record.dex_name.as_str(), record.string_idx))
            {
                return Err(DataProtectionError::Metadata(
                    "retrace record is invalid or duplicated".into(),
                ));
            }
        }
        Ok(())
    }

    /// Returns every possible old spelling for this new spelling: overloaded
    /// identities are never collapsed into a misleading single retrace result.
    #[must_use]
    pub fn candidates(&self, dex_name: &str, obfuscated: &str) -> Vec<&RetraceRecord> {
        self.records
            .iter()
            .filter(|r| r.dex_name == dex_name && r.obfuscated == obfuscated)
            .collect()
    }
}

fn canonical_dex_name(value: &str) -> bool {
    if value == "classes.dex" {
        return true;
    }
    let Some(digits) = value
        .strip_prefix("classes")
        .and_then(|s| s.strip_suffix(".dex"))
    else {
        return false;
    };
    !digits.starts_with('0') && digits.parse::<u32>().is_ok_and(|n| n >= 2)
}

/// Seal one private build map without exposing raw JSON as an artifact.
pub fn seal_retrace_map(schedule: &KeySchedule, map: &RetraceMap) -> Result<Vec<u8>> {
    map.validate(schedule)?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(map)
            .map_err(|_| DataProtectionError::Metadata("unable to encode retrace map".into()))?,
    );
    if plaintext.len() > MAX_RETRACE_PLAINTEXT {
        return Err(DataProtectionError::Metadata(
            "retrace payload exceeds the protected size limit".into(),
        ));
    }
    seal(
        schedule,
        ContainerKind::Generic,
        &logical_id(&map.apk_sha256),
        plaintext.as_slice(),
    )
}

/// The caller must supply the exact expected APK hash; guessing identities,
/// wrong build keys and edited ciphertext fail authentication.
pub fn open_retrace_map(
    schedule: &KeySchedule,
    expected_apk_sha256: &str,
    protected: &[u8],
) -> Result<RetraceMap> {
    if expected_apk_sha256.len() != 64
        || !expected_apk_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || protected.len() > MAX_RETRACE_PLAINTEXT + crate::container::CONTAINER_HEADER_LEN + 16
    {
        return Err(DataProtectionError::Metadata(
            "invalid expected hash or protected map size".into(),
        ));
    }
    let plaintext = Zeroizing::new(open(
        schedule,
        ContainerKind::Generic,
        &logical_id(expected_apk_sha256),
        protected,
    )?);
    let map: RetraceMap = serde_json::from_slice(plaintext.as_slice())
        .map_err(|_| DataProtectionError::Metadata("invalid retrace payload".into()))?;
    map.validate(schedule)?;
    if map.apk_sha256 != expected_apk_sha256 {
        return Err(DataProtectionError::AuthenticationFailed);
    }
    Ok(map)
}

fn logical_id(apk_sha256: &str) -> String {
    format!("{RETRACE_DOMAIN}{apk_sha256}")
}

#[cfg(test)]
mod tests {
    use super::{open_retrace_map, seal_retrace_map, RetraceMap, RetraceRecord, RETRACE_SCHEMA};
    use crate::{BuildIdentity, KeySchedule};

    fn schedule(build: &str, secret: u8) -> KeySchedule {
        KeySchedule::new(
            &[secret; 32],
            BuildIdentity::new("com.nexora.app", build).expect("build identity"),
        )
        .expect("key schedule")
    }

    fn demo(schedule: &KeySchedule) -> RetraceMap {
        RetraceMap::new(
            schedule,
            "a".repeat(64),
            vec![RetraceRecord {
                dex_name: "classes2.dex".into(),
                string_idx: 12,
                original: "Lcom/private/Secret;".into(),
                obfuscated: "Lcom/private/Abcdef;".into(),
                symbols: vec!["class:2".into()],
            }],
        )
        .expect("private map")
    }

    #[test]
    fn roundtrip_authenticated_and_candidates_preserve_identity() {
        let key = schedule("test-build", 7);
        let doc = demo(&key);
        let bytes = seal_retrace_map(&key, &doc).expect("seal");
        assert!(!bytes.windows("Secret".len()).any(|w| w == b"Secret"));
        let opened = open_retrace_map(&key, &"a".repeat(64), &bytes).expect("open");
        assert_eq!(opened, doc);
        assert_eq!(opened.schema, RETRACE_SCHEMA);
        assert_eq!(
            opened
                .candidates("classes2.dex", "Lcom/private/Abcdef;")
                .len(),
            1
        );
    }

    #[test]
    fn reject_tampering_wrong_key_wrong_build_and_apk() {
        let key = schedule("test-build", 7);
        let mut sealed = seal_retrace_map(&key, &demo(&key)).expect("seal");
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open_retrace_map(&key, &"a".repeat(64), &sealed).is_err());
        let original = seal_retrace_map(&key, &demo(&key)).expect("seal");
        assert!(open_retrace_map(&schedule("test-build", 8), &"a".repeat(64), &original).is_err());
        assert!(open_retrace_map(&schedule("other-build", 7), &"a".repeat(64), &original).is_err());
        assert!(open_retrace_map(&key, &"b".repeat(64), &original).is_err());
        assert!(open_retrace_map(&key, &"a".repeat(63), &original).is_err());
    }

    #[test]
    fn reject_duplicate_or_empty_records() {
        let key = schedule("test-build", 7);
        let entry = demo(&key).records[0].clone();
        assert!(RetraceMap::new(&key, "a".repeat(64), vec![entry.clone(), entry]).is_err());
        assert!(RetraceMap::new(&key, "a".repeat(64), vec![]).is_err());
    }

    #[test]
    fn debug_does_not_expose_original_names() {
        let key = schedule("test-build", 7);
        let map = demo(&key);
        assert!(!format!("{map:?}").contains("Secret"));
        assert!(!format!("{:?}", map.records[0]).contains("Secret"));
    }
}
