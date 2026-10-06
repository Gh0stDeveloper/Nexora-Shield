use crate::error::{IntegrityError, Result};
use crate::hash::{hash_components, Sha256Digest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificatePolicy {
    ExactCurrent,
    CurrentOrLineage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateBinding {
    pub policy: CertificatePolicy,
    pub allowed_current: BTreeSet<Sha256Digest>,
    pub allowed_lineage: BTreeSet<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateObservation {
    pub current: BTreeSet<Sha256Digest>,
    pub lineage: BTreeSet<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateCheck {
    pub matched: bool,
    pub expected_fingerprint: Sha256Digest,
    pub observed_fingerprint: Sha256Digest,
    pub reason: String,
}

impl CertificateBinding {
    pub fn new(
        policy: CertificatePolicy,
        allowed_current: impl IntoIterator<Item = Sha256Digest>,
        allowed_lineage: impl IntoIterator<Item = Sha256Digest>,
    ) -> Result<Self> {
        let allowed_current = allowed_current.into_iter().collect::<BTreeSet<_>>();
        let allowed_lineage = allowed_lineage.into_iter().collect::<BTreeSet<_>>();
        if allowed_current.is_empty() {
            return Err(IntegrityError::InvalidCertificateBinding(
                "at least one current signer digest is required".into(),
            ));
        }

        Ok(Self {
            policy,
            allowed_current,
            allowed_lineage,
        })
    }

    #[must_use]
    pub fn fingerprint(&self) -> Sha256Digest {
        let policy = match self.policy {
            CertificatePolicy::ExactCurrent => b"exact-current".as_slice(),
            CertificatePolicy::CurrentOrLineage => b"current-or-lineage".as_slice(),
        };
        let mut components = Vec::<Vec<u8>>::new();
        components.push(policy.to_vec());
        for digest in &self.allowed_current {
            components.push(digest.as_bytes().to_vec());
        }
        components.push(b"lineage".to_vec());
        for digest in &self.allowed_lineage {
            components.push(digest.as_bytes().to_vec());
        }
        hash_components(
            b"NexoraShield:D:certificate-binding:v1",
            components.iter().map(Vec::as_slice),
        )
    }

    #[must_use]
    pub fn verify(&self, observation: &CertificateObservation) -> CertificateCheck {
        let current_match = !self.allowed_current.is_disjoint(&observation.current);
        let lineage_match = !self.allowed_current.is_disjoint(&observation.lineage)
            || !self.allowed_lineage.is_disjoint(&observation.current)
            || !self.allowed_lineage.is_disjoint(&observation.lineage);

        let matched = match self.policy {
            CertificatePolicy::ExactCurrent => current_match,
            CertificatePolicy::CurrentOrLineage => current_match || lineage_match,
        };

        CertificateCheck {
            matched,
            expected_fingerprint: self.fingerprint(),
            observed_fingerprint: observation.fingerprint(),
            reason: if matched {
                "signer certificate matches configured binding".into()
            } else {
                "observed signer/lineage does not match configured binding".into()
            },
        }
    }
}

impl CertificateObservation {
    pub fn new(
        current: impl IntoIterator<Item = Sha256Digest>,
        lineage: impl IntoIterator<Item = Sha256Digest>,
    ) -> Result<Self> {
        let current = current.into_iter().collect::<BTreeSet<_>>();
        let lineage = lineage.into_iter().collect::<BTreeSet<_>>();
        if current.is_empty() {
            return Err(IntegrityError::InvalidCertificateBinding(
                "observed current signer set must not be empty".into(),
            ));
        }
        Ok(Self { current, lineage })
    }

    #[must_use]
    pub fn fingerprint(&self) -> Sha256Digest {
        let mut components = Vec::<Vec<u8>>::new();
        for digest in &self.current {
            components.push(digest.as_bytes().to_vec());
        }
        components.push(b"lineage".to_vec());
        for digest in &self.lineage {
            components.push(digest.as_bytes().to_vec());
        }
        hash_components(
            b"NexoraShield:D:certificate-observation:v1",
            components.iter().map(Vec::as_slice),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageBinding {
    pub application_id: String,
    pub version_code: u64,
    pub split_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageObservation {
    pub application_id: String,
    pub version_code: u64,
    pub split_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageCheck {
    pub matched: bool,
    pub expected_fingerprint: Sha256Digest,
    pub observed_fingerprint: Sha256Digest,
    pub reason: String,
}

impl PackageBinding {
    pub fn new(
        application_id: impl Into<String>,
        version_code: u64,
        split_name: Option<String>,
    ) -> Result<Self> {
        let binding = Self {
            application_id: application_id.into(),
            version_code,
            split_name,
        };
        validate_package_components(&binding.application_id, binding.split_name.as_deref())?;
        Ok(binding)
    }

    #[must_use]
    pub fn fingerprint(&self) -> Sha256Digest {
        package_fingerprint(
            &self.application_id,
            self.version_code,
            self.split_name.as_deref(),
        )
    }

    #[must_use]
    pub fn verify(&self, observed: &PackageObservation) -> PackageCheck {
        let matched = self.application_id == observed.application_id
            && self.version_code == observed.version_code
            && self.split_name == observed.split_name;
        PackageCheck {
            matched,
            expected_fingerprint: self.fingerprint(),
            observed_fingerprint: observed.fingerprint(),
            reason: if matched {
                "package identity matches protected build".into()
            } else {
                "package name/version/split identity differs from protected build".into()
            },
        }
    }
}

impl PackageObservation {
    pub fn new(
        application_id: impl Into<String>,
        version_code: u64,
        split_name: Option<String>,
    ) -> Result<Self> {
        let observation = Self {
            application_id: application_id.into(),
            version_code,
            split_name,
        };
        validate_package_components(
            &observation.application_id,
            observation.split_name.as_deref(),
        )?;
        Ok(observation)
    }

    #[must_use]
    pub fn fingerprint(&self) -> Sha256Digest {
        package_fingerprint(
            &self.application_id,
            self.version_code,
            self.split_name.as_deref(),
        )
    }
}

fn validate_package_components(application_id: &str, split_name: Option<&str>) -> Result<()> {
    if application_id.trim().is_empty()
        || application_id.as_bytes().contains(&0)
        || application_id.starts_with('.')
        || application_id.ends_with('.')
        || application_id.contains("..")
    {
        return Err(IntegrityError::InvalidPackageIdentity(
            "application_id is empty or malformed".into(),
        ));
    }
    if let Some(split) = split_name {
        if split.is_empty() || split.as_bytes().contains(&0) {
            return Err(IntegrityError::InvalidPackageIdentity(
                "split_name must be non-empty and contain no NUL".into(),
            ));
        }
    }
    Ok(())
}

fn package_fingerprint(
    application_id: &str,
    version_code: u64,
    split_name: Option<&str>,
) -> Sha256Digest {
    let version = version_code.to_le_bytes();
    hash_components(
        b"NexoraShield:D:package-binding:v1",
        [
            application_id.as_bytes(),
            version.as_slice(),
            split_name.unwrap_or("").as_bytes(),
        ],
    )
}
