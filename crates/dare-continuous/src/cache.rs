use std::collections::BTreeMap;

use dare_security_evidence::Verdict;
use serde::{Deserialize, Serialize};

use crate::reuse::{can_reuse, ReuseCandidate};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheEntry {
    pub key_digest: String,
    pub baseline_snapshot_digest: String,
    pub verdict: Option<Verdict>,
    pub evidence_ids: Vec<String>,
    pub dependency_digests: BTreeMap<String, Option<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct ValidationCache {
    entries: BTreeMap<String, CacheEntry>,
}

impl ValidationCache {
    pub fn insert(&mut self, id: String, entry: CacheEntry) {
        self.entries.insert(id, entry);
    }

    pub fn get(
        &self,
        id: &str,
        expected_key_digest: &str,
        expected_baseline_digest: &str,
        candidate_dependencies: &BTreeMap<String, Option<String>>,
    ) -> Option<&CacheEntry> {
        let entry = self.entries.get(id)?;
        if entry.key_digest != expected_key_digest || entry.evidence_ids.is_empty() {
            return None;
        }
        let decision = can_reuse(&ReuseCandidate {
            baseline_snapshot_digest: entry.baseline_snapshot_digest.clone(),
            expected_baseline_snapshot_digest: expected_baseline_digest.to_owned(),
            original_evidence_ids: entry.evidence_ids.clone(),
            baseline_dependencies: entry.dependency_digests.clone(),
            candidate_dependencies: candidate_dependencies.clone(),
        });
        decision.allowed.then_some(entry)
    }

    pub fn invalidate_by_dependency(&mut self, name: &str, digest: Option<&str>) {
        self.entries.retain(|_, entry| {
            entry
                .dependency_digests
                .get(name)
                .and_then(Option::as_deref)
                == digest
        });
    }
}
