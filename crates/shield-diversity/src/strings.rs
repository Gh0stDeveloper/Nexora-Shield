use crate::error::{DiversityError, Result};
use crate::seed::{DiversityDomain, SeedDeriver};
use nexora_shield_crypto::ProtectedString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringShard {
    pub shard_id: u16,
    pub opaque_name: String,
    pub logical_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringPartitionPlan {
    pub shards: Vec<StringShard>,
    pub fingerprint: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringShardEntry {
    pub opaque_id: String,
    pub container: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicStringShard {
    pub shard_id: u16,
    pub opaque_name: String,
    pub entries: Vec<StringShardEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringShardLocation {
    pub opaque_name: String,
    pub entry_index: usize,
}

#[derive(Clone, PartialEq, Eq)]
pub struct StringPartitionBuild {
    pub public_shards: Vec<PublicStringShard>,
    private_lookup: BTreeMap<String, StringShardLocation>,
}

impl StringPartitionBuild {
    #[must_use]
    pub fn private_lookup(&self) -> &BTreeMap<String, StringShardLocation> {
        &self.private_lookup
    }
}

impl fmt::Debug for StringPartitionBuild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StringPartitionBuild")
            .field("public_shards", &self.public_shards)
            .field("private_lookup", &"[REDACTED]")
            .field("private_lookup_entries", &self.private_lookup.len())
            .finish()
    }
}

impl StringPartitionPlan {
    pub fn derive(
        seed: &SeedDeriver,
        logical_ids: &[String],
        min_partitions: u16,
        max_partitions: u16,
    ) -> Result<Self> {
        if min_partitions == 0 || max_partitions < min_partitions {
            return Err(DiversityError::InvalidPartitionBounds);
        }

        let unique = logical_ids.iter().cloned().collect::<BTreeSet<_>>();
        if unique.is_empty() {
            return Ok(Self {
                shards: Vec::new(),
                fingerprint: empty_fingerprint(),
            });
        }

        let max_allowed = usize::from(max_partitions).min(unique.len());
        let min_allowed = usize::from(min_partitions).min(max_allowed).max(1);
        let span = max_allowed - min_allowed + 1;
        let selector = seed.derive_u64(DiversityDomain::StringPartition, b"partition-count")?;
        let partition_count = min_allowed
            + usize::try_from(selector % u64::try_from(span).unwrap_or(u64::MAX)).unwrap_or(0);

        let mut keyed = unique
            .into_iter()
            .map(|logical_id| {
                Ok((
                    seed.derive_u64(DiversityDomain::StringPartition, logical_id.as_bytes())?,
                    logical_id,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        keyed.sort_by(|(left_key, left), (right_key, right)| {
            left_key.cmp(right_key).then_with(|| left.cmp(right))
        });
        let ordered = keyed
            .into_iter()
            .map(|(_, logical_id)| logical_id)
            .collect::<Vec<_>>();

        let offset_selector =
            seed.derive_u64(DiversityDomain::StringPartition, b"partition-offset")?;
        let offset =
            usize::try_from(offset_selector % u64::try_from(partition_count).unwrap_or(u64::MAX))
                .unwrap_or(0);

        let mut buckets = vec![Vec::<String>::new(); partition_count];
        for (index, logical_id) in ordered.into_iter().enumerate() {
            let shard = (index + offset) % partition_count;
            buckets[shard].push(logical_id);
        }

        let mut shards = Vec::with_capacity(partition_count);
        for (index, logical_ids) in buckets.into_iter().enumerate() {
            let shard_id =
                u16::try_from(index).map_err(|_| DiversityError::InvalidPartitionBounds)?;
            let label = format!("shard:{shard_id}");
            let token = seed.derive_u64(DiversityDomain::StringPartition, label.as_bytes())?;
            shards.push(StringShard {
                shard_id,
                opaque_name: format!("s{token:016x}.nsc"),
                logical_ids,
            });
        }

        let fingerprint = partition_fingerprint(&shards);
        Ok(Self {
            shards,
            fingerprint,
        })
    }

    pub fn materialize(&self, protected: &[ProtectedString]) -> Result<StringPartitionBuild> {
        let planned_ids = self
            .shards
            .iter()
            .flat_map(|shard| shard.logical_ids.iter().cloned())
            .collect::<BTreeSet<_>>();
        let mut by_logical_id = BTreeMap::<String, &ProtectedString>::new();

        for item in protected {
            let logical_id = item.record.logical_id.clone();
            if !planned_ids.contains(&logical_id) {
                return Err(DiversityError::UnplannedStringContainer(logical_id));
            }
            if by_logical_id.insert(logical_id.clone(), item).is_some() {
                return Err(DiversityError::DuplicateStringContainer(logical_id));
            }
        }

        let mut public_shards = Vec::with_capacity(self.shards.len());
        let mut private_lookup = BTreeMap::new();

        for shard in &self.shards {
            let mut entries = Vec::with_capacity(shard.logical_ids.len());
            for logical_id in &shard.logical_ids {
                let item = by_logical_id
                    .get(logical_id)
                    .ok_or_else(|| DiversityError::MissingStringContainer(logical_id.clone()))?;
                let entry_index = entries.len();
                entries.push(StringShardEntry {
                    opaque_id: item.record.opaque_id.clone(),
                    container: item.container.clone(),
                });
                private_lookup.insert(
                    logical_id.clone(),
                    StringShardLocation {
                        opaque_name: shard.opaque_name.clone(),
                        entry_index,
                    },
                );
            }
            public_shards.push(PublicStringShard {
                shard_id: shard.shard_id,
                opaque_name: shard.opaque_name.clone(),
                entries,
            });
        }

        Ok(StringPartitionBuild {
            public_shards,
            private_lookup,
        })
    }

    #[must_use]
    pub fn total_items(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.logical_ids.len())
            .sum()
    }

    #[must_use]
    pub fn all_shards_non_empty(&self) -> bool {
        self.shards
            .iter()
            .all(|shard| !shard.logical_ids.is_empty())
    }
}

fn partition_fingerprint(shards: &[StringShard]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"nexora-shield/string-partitions/v1");
    for shard in shards {
        hasher.update(shard.shard_id.to_le_bytes());
        hasher.update(shard.opaque_name.as_bytes());
        hasher.update([0]);
        for logical_id in &shard.logical_ids {
            hasher.update(
                u64::try_from(logical_id.len())
                    .unwrap_or(u64::MAX)
                    .to_le_bytes(),
            );
            hasher.update(logical_id.as_bytes());
        }
    }
    hasher.finalize().into()
}

fn empty_fingerprint() -> [u8; 32] {
    Sha256::digest(b"nexora-shield/string-partitions/v1:empty").into()
}
