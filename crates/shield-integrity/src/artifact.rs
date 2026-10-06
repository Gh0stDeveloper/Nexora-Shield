use crate::error::{IntegrityError, Result};
use crate::hash::Sha256Digest;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Resource,
    Native,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactIntegrity {
    pub path: String,
    pub kind: ArtifactKind,
    pub size: u64,
    pub digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactCheck {
    pub path: String,
    pub kind: ArtifactKind,
    pub matched: bool,
    pub expected_size: u64,
    pub observed_size: u64,
    pub expected: Sha256Digest,
    pub observed: Sha256Digest,
}

impl ArtifactIntegrity {
    pub fn build(path: impl Into<String>, kind: ArtifactKind, bytes: &[u8]) -> Result<Self> {
        let path = normalize_path(&path.into())?;
        let size = u64::try_from(bytes.len())
            .map_err(|_| IntegrityError::InvalidArtifact("artifact size does not fit u64".into()))?;
        Ok(Self {
            path,
            kind,
            size,
            digest: Sha256Digest::of(bytes),
        })
    }

    pub fn verify(&self, bytes: &[u8]) -> Result<ArtifactCheck> {
        let observed_size = u64::try_from(bytes.len())
            .map_err(|_| IntegrityError::InvalidArtifact("artifact size does not fit u64".into()))?;
        let observed = Sha256Digest::of(bytes);
        Ok(ArtifactCheck {
            path: self.path.clone(),
            kind: self.kind,
            matched: observed_size == self.size && observed == self.digest,
            expected_size: self.size,
            observed_size,
            expected: self.digest,
            observed,
        })
    }
}

pub fn normalize_path(path: &str) -> Result<String> {
    if path.is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.as_bytes().contains(&0)
        || path.split('/').any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(IntegrityError::InvalidArtifact(format!(
            "unsafe artifact path '{path}'"
        )));
    }
    Ok(path.to_owned())
}
