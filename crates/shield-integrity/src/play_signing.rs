use crate::error::{IntegrityError, Result};
use crate::hash::Sha256Digest;
use crate::identity::{CertificateBinding, CertificatePolicy};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayAppSigningConfig {
    pub upload_certificate: Option<Sha256Digest>,
    pub delivery_current: BTreeSet<Sha256Digest>,
    pub delivery_lineage: BTreeSet<Sha256Digest>,
}

impl PlayAppSigningConfig {
    pub fn new(
        upload_certificate: Option<Sha256Digest>,
        delivery_current: impl IntoIterator<Item = Sha256Digest>,
        delivery_lineage: impl IntoIterator<Item = Sha256Digest>,
    ) -> Result<Self> {
        let delivery_current = delivery_current.into_iter().collect::<BTreeSet<_>>();
        let delivery_lineage = delivery_lineage.into_iter().collect::<BTreeSet<_>>();

        if delivery_current.is_empty() {
            return Err(IntegrityError::InvalidCertificateBinding(
                "Play App Signing requires at least one delivery signer digest".into(),
            ));
        }

        Ok(Self {
            upload_certificate,
            delivery_current,
            delivery_lineage,
        })
    }

    pub fn runtime_binding(&self, policy: CertificatePolicy) -> Result<CertificateBinding> {
        CertificateBinding::new(
            policy,
            self.delivery_current.iter().copied(),
            self.delivery_lineage.iter().copied(),
        )
    }

    #[must_use]
    pub fn upload_certificate_is_runtime_signer(&self) -> bool {
        self.upload_certificate
            .is_some_and(|upload| self.delivery_current.contains(&upload))
    }
}

#[cfg(test)]
mod tests {
    use super::PlayAppSigningConfig;
    use crate::{CertificateObservation, CertificatePolicy, Sha256Digest};

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest([byte; 32])
    }

    #[test]
    fn upload_certificate_is_not_implicitly_trusted_at_runtime() -> crate::Result<()> {
        let config = PlayAppSigningConfig::new(Some(digest(0x11)), [digest(0x22)], [digest(0x33)])?;
        let binding = config.runtime_binding(CertificatePolicy::CurrentOrLineage)?;

        let upload_observation = CertificateObservation::new([digest(0x11)], [])?;
        assert!(!binding.verify(&upload_observation).matched);

        let delivery_observation = CertificateObservation::new([digest(0x22)], [])?;
        assert!(binding.verify(&delivery_observation).matched);
        Ok(())
    }
}
