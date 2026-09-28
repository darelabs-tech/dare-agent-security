//! Evidence index (BLUEPRINT §4.4 rule 5).
//!
//! Every record of an engine's evidence file is decoded as a Cycle 001
//! `SecurityEvidence` and validated before any fact cites it. The property a
//! record decides is read from the engine's extension namespace, under the
//! key that engine uses (the key is not uniform across engines).
use std::collections::BTreeMap;

use dare_attack_graph::v2::GuardVerdict;
use dare_security_evidence::{validate, SecurityEvidence, Verdict};

use crate::{
    error::{Refusal, Result},
    ids::EngineSlug,
};

/// Engine namespace and the key under which it records the property.
pub const PROPERTY_KEYS: [(&str, &str); 9] = [
    ("dare.prompt-injection.v1", "property_id"),
    ("dare.tool-security.v1", "property_id"),
    ("dare.identity-security.v1", "property_id"),
    ("dare.memory-security.v1", "property_id"),
    ("dare.rag-security.v1", "property_id"),
    ("dare.mcp-auth-security.v1", "property"),
    ("dare.supply-chain-security.v1", "property"),
    ("dare.a2a-security.v1", "property"),
    ("dare.multi-turn-security.v1", "property"),
];

pub fn namespace(engine: EngineSlug) -> Option<&'static str> {
    let ns = match engine {
        EngineSlug::PromptInjection => "dare.prompt-injection.v1",
        EngineSlug::Tool => "dare.tool-security.v1",
        EngineSlug::Identity => "dare.identity-security.v1",
        EngineSlug::Memory => "dare.memory-security.v1",
        EngineSlug::Rag => "dare.rag-security.v1",
        EngineSlug::McpAuth => "dare.mcp-auth-security.v1",
        EngineSlug::SupplyChain => "dare.supply-chain-security.v1",
        EngineSlug::A2a => "dare.a2a-security.v1",
        EngineSlug::MultiTurn => "dare.multi-turn-security.v1",
        EngineSlug::Remote => return None,
    };
    Some(ns)
}

pub fn guard_verdict(verdict: Verdict) -> GuardVerdict {
    match verdict {
        Verdict::Pass => GuardVerdict::Pass,
        Verdict::Fail => GuardVerdict::Fail,
        Verdict::Inconclusive => GuardVerdict::Inconclusive,
        Verdict::Error => GuardVerdict::Error,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedRecord {
    pub id: String,
    pub property: String,
    pub verdict: GuardVerdict,
    pub namespace: &'static str,
    /// `extensions["dare.remote"]` is present (Cycle 022 re-tagged record).
    pub remote: bool,
}

#[derive(Debug, Clone, Default)]
pub struct EvidenceIndex {
    records: Vec<IndexedRecord>,
    by_id: BTreeMap<String, usize>,
}

impl EvidenceIndex {
    /// Decodes and validates every record of an evidence file. Every engine
    /// writes a bare array except multi-turn, which writes
    /// `{schema_version, records, coverage}`.
    pub fn build(index: usize, engine: EngineSlug, value: &serde_json::Value) -> Result<Self> {
        let records = match engine {
            EngineSlug::MultiTurn => &value["records"],
            _ => value,
        };
        let items = records.as_array().ok_or(Refusal::InvalidDocument {
            index,
            file: "evidence",
            reason: "not an array of evidence records",
        })?;
        let mut out = Self::default();
        for (record, item) in items.iter().enumerate() {
            let invalid = || Refusal::InvalidEvidence { index, record };
            let evidence: SecurityEvidence =
                serde_json::from_value(item.clone()).map_err(|_| invalid())?;
            validate(&evidence).map_err(|_| invalid())?;
            let extensions = evidence.extensions.as_ref().ok_or_else(invalid)?;
            let (namespace, property) = PROPERTY_KEYS
                .iter()
                .find_map(|(ns, key)| {
                    extensions
                        .get(*ns)
                        .and_then(|payload| payload.get(*key))
                        .and_then(|p| p.as_str())
                        .map(|p| (*ns, p.to_owned()))
                })
                .ok_or_else(invalid)?;
            if out.by_id.contains_key(&evidence.id) {
                return Err(invalid().into());
            }
            out.by_id.insert(evidence.id.clone(), out.records.len());
            out.records.push(IndexedRecord {
                id: evidence.id,
                property,
                verdict: guard_verdict(evidence.verdict),
                namespace,
                remote: extensions.contains_key("dare.remote"),
            });
        }
        Ok(out)
    }

    pub fn records(&self) -> &[IndexedRecord] {
        &self.records
    }

    pub fn get(&self, id: &str) -> Option<&IndexedRecord> {
        self.by_id.get(id).map(|&i| &self.records[i])
    }

    /// Every id a result lists must be present.
    pub fn require_all(&self, index: usize, ids: &[String]) -> Result<()> {
        for (position, id) in ids.iter().enumerate() {
            if !self.by_id.contains_key(id) {
                return Err(Refusal::UnknownEvidenceId { index, position }.into());
            }
        }
        Ok(())
    }

    /// Record ids for a property, sorted.
    pub fn ids_for(&self, property: &str) -> Vec<String> {
        let mut ids: Vec<String> = self
            .records
            .iter()
            .filter(|r| r.property == property)
            .map(|r| r.id.clone())
            .collect();
        ids.sort();
        ids
    }

    /// Every record id, sorted.
    pub fn all_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.records.iter().map(|r| r.id.clone()).collect();
        ids.sort();
        ids
    }
}
