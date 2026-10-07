use serde::{Deserialize, Serialize};

pub const PRODUCTION_LINKER_ARGS: [&str; 4] = [
    "-Wl,-z,relro,-z,now",
    "-Wl,--gc-sections",
    "-Wl,--exclude-libs,ALL",
    "-Wl,--build-id=none",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardeningProfile {
    pub position_independent: bool,
    pub relro: bool,
    pub bind_now: bool,
    pub garbage_collect_sections: bool,
    pub strip_symbols: bool,
    pub hide_archive_symbols: bool,
    pub build_id_disabled: bool,
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
            position_independent: true,
            relro: true,
            bind_now: true,
            garbage_collect_sections: true,
            strip_symbols: true,
            hide_archive_symbols: true,
            build_id_disabled: true,
        }
    }

    #[must_use]
    pub const fn is_production_hardened(self) -> bool {
        self.position_independent
            && self.relro
            && self.bind_now
            && self.garbage_collect_sections
            && self.strip_symbols
            && self.hide_archive_symbols
            && self.build_id_disabled
    }
}
