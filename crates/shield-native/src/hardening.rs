use serde::{Deserialize, Serialize};

pub const PRODUCTION_LINKER_ARGS: [&str; 4] = [
    "-Wl,-z,relro,-z,now",
    "-Wl,--gc-sections",
    "-Wl,--exclude-libs,ALL",
    "-Wl,--build-id=none",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardeningFeature {
    PositionIndependent,
    Relro,
    BindNow,
    GarbageCollectSections,
    StripSymbols,
    HideArchiveSymbols,
    DisableBuildId,
}

impl HardeningFeature {
    const fn mask(self) -> u16 {
        match self {
            Self::PositionIndependent => 1 << 0,
            Self::Relro => 1 << 1,
            Self::BindNow => 1 << 2,
            Self::GarbageCollectSections => 1 << 3,
            Self::StripSymbols => 1 << 4,
            Self::HideArchiveSymbols => 1 << 5,
            Self::DisableBuildId => 1 << 6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningProfile {
    bits: u16,
}

impl Default for HardeningProfile {
    fn default() -> Self {
        Self::production()
    }
}

impl HardeningProfile {
    #[must_use]
    pub const fn production() -> Self {
        Self {
            bits: HardeningFeature::PositionIndependent.mask()
                | HardeningFeature::Relro.mask()
                | HardeningFeature::BindNow.mask()
                | HardeningFeature::GarbageCollectSections.mask()
                | HardeningFeature::StripSymbols.mask()
                | HardeningFeature::HideArchiveSymbols.mask()
                | HardeningFeature::DisableBuildId.mask(),
        }
    }

    #[must_use]
    pub const fn enables(self, feature: HardeningFeature) -> bool {
        self.bits & feature.mask() != 0
    }

    #[must_use]
    pub const fn is_production_hardened(self) -> bool {
        let production = Self::production();
        self.bits == production.bits
    }
}
