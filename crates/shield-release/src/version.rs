use crate::error::{ReleaseError, Result};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseChannel {
    Rc,
    Stable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub rc: Option<u32>,
}

impl ReleaseVersion {
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.strip_prefix('v').unwrap_or(value);
        let (core, rc) = if let Some((core, rc)) = value.split_once("-rc.") {
            let number = rc.parse::<u32>().map_err(|_| {
                ReleaseError::InvalidVersion("RC suffix must be -rc.<positive integer>".into())
            })?;
            if number == 0 {
                return Err(ReleaseError::InvalidVersion(
                    "RC number must be greater than zero".into(),
                ));
            }
            (core, Some(number))
        } else if value.contains('-') {
            return Err(ReleaseError::InvalidVersion(
                "only -rc.N prereleases are supported for 1.0".into(),
            ));
        } else {
            (value, None)
        };

        let mut parts = core.split('.');
        let major = parse_component(parts.next(), "major")?;
        let minor = parse_component(parts.next(), "minor")?;
        let patch = parse_component(parts.next(), "patch")?;
        if parts.next().is_some() {
            return Err(ReleaseError::InvalidVersion(
                "version must contain exactly major.minor.patch".into(),
            ));
        }

        Ok(Self {
            major,
            minor,
            patch,
            rc,
        })
    }

    #[must_use]
    pub const fn channel(&self) -> ReleaseChannel {
        if self.rc.is_some() {
            ReleaseChannel::Rc
        } else {
            ReleaseChannel::Stable
        }
    }

    pub fn require_1_0_channel(&self, channel: ReleaseChannel) -> Result<()> {
        if (self.major, self.minor, self.patch) != (1, 0, 0) {
            return Err(ReleaseError::InvalidVersion(
                "Phase N release must target version 1.0.0".into(),
            ));
        }
        if self.channel() != channel {
            return Err(ReleaseError::InvalidVersion(format!(
                "expected {channel:?} channel, found {:?}",
                self.channel()
            )));
        }
        Ok(())
    }
}

impl fmt::Display for ReleaseVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(rc) = self.rc {
            write!(formatter, "-rc.{rc}")?;
        }
        Ok(())
    }
}

fn parse_component(value: Option<&str>, label: &str) -> Result<u32> {
    value
        .ok_or_else(|| {
            ReleaseError::InvalidVersion(format!("missing {label} version component"))
        })?
        .parse::<u32>()
        .map_err(|_| ReleaseError::InvalidVersion(format!("invalid {label} version component")))
}
