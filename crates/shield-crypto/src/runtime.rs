use crate::container::{open, ContainerKind};
use crate::error::{DataProtectionError, Result};
use crate::key::{KeySchedule, ITEM_ID_LEN};
use std::collections::BTreeMap;
use std::fmt;
use std::ops::Deref;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

#[derive(PartialEq, Eq)]
pub struct SensitiveBytes {
    bytes: Vec<u8>,
}

impl SensitiveBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Clone for SensitiveBytes {
    fn clone(&self) -> Self {
        Self::new(self.bytes.clone())
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveBytes")
            .field("bytes", &"[REDACTED]")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl Deref for SensitiveBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(PartialEq, Eq)]
pub struct SensitiveString {
    value: String,
}

impl SensitiveString {
    pub fn from_bytes(bytes: SensitiveBytes) -> Result<Self> {
        let value = String::from_utf8(bytes.as_slice().to_vec())
            .map_err(|_| DataProtectionError::InvalidUtf8)?;
        Ok(Self { value })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl Clone for SensitiveString {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
        }
    }
}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveString")
            .field("value", &"[REDACTED]")
            .field("len", &self.value.len())
            .finish()
    }
}

impl Deref for SensitiveString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Drop for SensitiveString {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    Disabled,
    Bounded {
        max_entries: usize,
        max_bytes: usize,
        ttl: Duration,
    },
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self::Disabled
    }
}

#[derive(Debug)]
struct CacheEntry {
    value: SensitiveBytes,
    inserted_at: Instant,
    last_touch: u64,
}

#[derive(Debug)]
pub struct DecryptRuntime {
    schedule: KeySchedule,
    policy: CachePolicy,
    cache: BTreeMap<[u8; ITEM_ID_LEN], CacheEntry>,
    cache_bytes: usize,
    touch_counter: u64,
}

impl DecryptRuntime {
    #[must_use]
    pub fn new(schedule: KeySchedule, policy: CachePolicy) -> Self {
        Self {
            schedule,
            policy,
            cache: BTreeMap::new(),
            cache_bytes: 0,
            touch_counter: 0,
        }
    }

    pub fn decrypt(
        &mut self,
        kind: ContainerKind,
        logical_id: &str,
        container: &[u8],
    ) -> Result<SensitiveBytes> {
        let item_id = self.schedule.opaque_item_id(kind.domain(), logical_id)?;
        self.touch_counter = self.touch_counter.wrapping_add(1);
        self.prune_expired();

        if let Some(entry) = self.cache.get_mut(&item_id) {
            entry.last_touch = self.touch_counter;
            return Ok(entry.value.clone());
        }

        let plaintext = SensitiveBytes::new(open(&self.schedule, kind, logical_id, container)?);
        self.insert_cache(item_id, plaintext.clone());
        Ok(plaintext)
    }

    pub fn decrypt_string(
        &mut self,
        logical_id: &str,
        container: &[u8],
    ) -> Result<SensitiveString> {
        SensitiveString::from_bytes(self.decrypt(ContainerKind::String, logical_id, container)?)
    }

    pub fn clear(&mut self) {
        self.cache.clear();
        self.cache_bytes = 0;
    }

    #[must_use]
    pub fn cached_entries(&self) -> usize {
        self.cache.len()
    }

    #[must_use]
    pub const fn cached_bytes(&self) -> usize {
        self.cache_bytes
    }

    fn insert_cache(&mut self, item_id: [u8; ITEM_ID_LEN], value: SensitiveBytes) {
        let CachePolicy::Bounded {
            max_entries,
            max_bytes,
            ttl: _,
        } = self.policy
        else {
            return;
        };

        if max_entries == 0 || max_bytes == 0 || value.len() > max_bytes {
            return;
        }

        while self.cache.len() >= max_entries
            || self.cache_bytes.saturating_add(value.len()) > max_bytes
        {
            if !self.evict_lru() {
                return;
            }
        }

        self.cache_bytes = self.cache_bytes.saturating_add(value.len());
        self.cache.insert(
            item_id,
            CacheEntry {
                value,
                inserted_at: Instant::now(),
                last_touch: self.touch_counter,
            },
        );
    }

    fn prune_expired(&mut self) {
        let CachePolicy::Bounded { ttl, .. } = self.policy else {
            return;
        };
        let now = Instant::now();
        let expired = self
            .cache
            .iter()
            .filter_map(|(id, entry)| (now.duration_since(entry.inserted_at) >= ttl).then_some(*id))
            .collect::<Vec<_>>();

        for id in expired {
            if let Some(entry) = self.cache.remove(&id) {
                self.cache_bytes = self.cache_bytes.saturating_sub(entry.value.len());
            }
        }
    }

    fn evict_lru(&mut self) -> bool {
        let candidate = self
            .cache
            .iter()
            .min_by_key(|(_, entry)| entry.last_touch)
            .map(|(id, _)| *id);
        let Some(id) = candidate else {
            return false;
        };
        if let Some(entry) = self.cache.remove(&id) {
            self.cache_bytes = self.cache_bytes.saturating_sub(entry.value.len());
            true
        } else {
            false
        }
    }
}

impl Drop for DecryptRuntime {
    fn drop(&mut self) {
        self.clear();
    }
}
