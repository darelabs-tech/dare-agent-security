//! Replay adapter: evaluate a sanitized local memory trace.
//!
//! Replay reads a file and decides nothing. It opens no database, cache or
//! vector store, contacts no provider, spawns no process, and performs none of
//! the actions the trace describes. Those are not policies applied at run time
//! — this module has no I/O beyond reading the trace path it was handed, and
//! [`MemoryTrace`] has no field that could name a store or an endpoint.
//!
//! A trace is admitted only when it survives, in order: a size bound, a version
//! check, the hostile-field sweep, its JSON Schema, `deny_unknown_fields`
//! decoding, a scenario-identity check and a canonical digest binding. The
//! digest is what makes replay reproducible rather than merely repeatable.
//!
//! A trace carries observations, never a verdict. There is deliberately no way
//! for a recorded trace to state the outcome it wants.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::canonical::digest;
use crate::error::{MemorySecurityError, Result};
use crate::harness::{HarnessAdapter, HarnessMode, RawTrialOutput, TrialRequest};
use crate::model::MemorySecurityScenario;
use crate::schema::{enforce_document_size, validate_trace_document};

/// A sanitized, previously recorded, local memory trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryTrace {
    pub schema_version: String,
    pub trace_id: String,
    /// The scenario this trace was recorded against.
    pub scenario_id: String,
    /// Always `REPLAY`. A trace cannot ask to be run any other way.
    pub mode: HarnessMode,
    /// Always `true`. Cycle 016 traces are synthetic by construction.
    pub synthetic: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub trials: Vec<RawTrialOutput>,
}

impl MemoryTrace {
    /// Structural checks the schema cannot express.
    pub fn validate(&self) -> Result<()> {
        if self.mode != HarnessMode::Replay {
            return Err(MemorySecurityError::refusal(format!(
                "trace `{}` declares mode `{}`; a recorded trace can only be replayed",
                self.trace_id,
                self.mode.as_str()
            )));
        }
        if !self.synthetic {
            // A trace claiming to be production evidence would let a report
            // present replayed observations as real-world memory validation.
            return Err(MemorySecurityError::refusal(format!(
                "trace `{}` does not declare itself synthetic; Cycle 016 replays synthetic \
                 traces only",
                self.trace_id
            )));
        }
        if self.trials.is_empty() {
            return Err(MemorySecurityError::invalid(format!(
                "trace `{}` contains no trials",
                self.trace_id
            )));
        }
        if self.trials.len() as u32 > crate::limits::HARD_MAX_TRIALS {
            return Err(MemorySecurityError::BudgetExhausted(format!(
                "trace `{}` carries {} trials; the hard maximum is {}",
                self.trace_id,
                self.trials.len(),
                crate::limits::HARD_MAX_TRIALS
            )));
        }

        for (index, trial) in self.trials.iter().enumerate() {
            // A recall result must answer a request the same trial recorded.
            // A result with no request could otherwise be carried into evidence
            // as matching something nobody can inspect.
            for result in &trial.recall_results {
                if !trial
                    .recall_requests
                    .iter()
                    .any(|request| request.request_id == result.request_id)
                {
                    return Err(MemorySecurityError::unknown_reference(format!(
                        "trace `{}` trial {index}: recall result `{}` answers a request the \
                         trial did not record",
                        self.trace_id, result.request_id
                    )));
                }
                if result.memory_ids.len() as u32 > crate::limits::MAX_RECALL_ITEMS_PER_REQUEST {
                    return Err(MemorySecurityError::BudgetExhausted(format!(
                        "trace `{}` trial {index}: a recall returned {} items; the bound is {}",
                        self.trace_id,
                        result.memory_ids.len(),
                        crate::limits::MAX_RECALL_ITEMS_PER_REQUEST
                    )));
                }
            }
        }

        Ok(())
    }

    /// Refuse a trace recorded against a different scenario.
    ///
    /// Without this, a trace of a permissive scenario could supply the passing
    /// observations for a stricter one.
    pub fn assert_matches(&self, scenario: &MemorySecurityScenario) -> Result<()> {
        if self.scenario_id != scenario.id {
            return Err(MemorySecurityError::refusal(format!(
                "trace `{}` was recorded against scenario `{}`, not `{}`",
                self.trace_id, self.scenario_id, scenario.id
            )));
        }
        Ok(())
    }

    /// Canonical digest of the trace content.
    pub fn digest(&self) -> Result<String> {
        digest(self)
    }
}

/// A trace loaded from disk, bound to the bytes it was loaded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedTrace {
    pub trace: MemoryTrace,
    pub content_digest: String,
    pub source_path: PathBuf,
}

/// Parse and validate a trace from raw bytes.
pub fn parse_trace(raw: &[u8], label: &str) -> Result<MemoryTrace> {
    enforce_document_size(raw, label)?;
    let value: serde_json::Value = serde_json::from_slice(raw)?;
    // Schema first, then the typed decode: two independent gates, so a field
    // slipping past one still has to survive the other.
    validate_trace_document(&value)?;
    let trace: MemoryTrace = serde_json::from_value(value)?;
    trace.validate()?;
    Ok(trace)
}

/// Load a trace from a local path.
///
/// The only I/O in this module. A path is a local file path; nothing here
/// resolves a URL, and no scheme is accepted or interpreted.
pub fn load_trace(path: &Path) -> Result<LoadedTrace> {
    let raw = std::fs::read(path)?;
    let label = format!("replay trace `{}`", path.display());
    let trace = parse_trace(&raw, &label)?;
    let content_digest = trace.digest()?;
    Ok(LoadedTrace {
        trace,
        content_digest,
        source_path: path.to_path_buf(),
    })
}

/// The replay adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayAdapter {
    loaded: LoadedTrace,
}

impl ReplayAdapter {
    pub fn new(loaded: LoadedTrace) -> Self {
        Self { loaded }
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        Ok(Self::new(load_trace(path)?))
    }

    pub fn trace(&self) -> &MemoryTrace {
        &self.loaded.trace
    }

    pub fn content_digest(&self) -> &str {
        &self.loaded.content_digest
    }

    pub fn source_path(&self) -> &Path {
        &self.loaded.source_path
    }

    pub fn available_trials(&self) -> u32 {
        self.loaded.trace.trials.len() as u32
    }

    /// Re-verify that the loaded trace still hashes to what it did at load.
    pub fn verify_binding(&self) -> Result<()> {
        let actual = self.loaded.trace.digest()?;
        if actual != self.loaded.content_digest {
            return Err(MemorySecurityError::DigestMismatch(format!(
                "replay trace `{}` no longer matches its load-time digest",
                self.loaded.trace.trace_id
            )));
        }
        Ok(())
    }
}

impl HarnessAdapter for ReplayAdapter {
    fn mode(&self) -> HarnessMode {
        HarnessMode::Replay
    }

    fn trial_capacity(&self) -> u32 {
        self.available_trials()
    }

    fn observe(&self, request: &TrialRequest<'_>) -> Result<RawTrialOutput> {
        self.loaded.trace.assert_matches(request.scenario)?;
        self.verify_binding()?;
        self.loaded
            .trace
            .trials
            .get(request.trial_index as usize)
            .cloned()
            // A trace that has run out of trials is a bounded failure, not an
            // opportunity to reuse an earlier trial's observations.
            .ok_or_else(|| {
                MemorySecurityError::invalid(format!(
                    "replay trace `{}` has {} trials; trial {} was requested",
                    self.loaded.trace.trace_id,
                    self.loaded.trace.trials.len(),
                    request.trial_index
                ))
            })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::harness::tests::scenario;
    use crate::harness::{normalize_checked, observed_recall_items};
    use serde_json::json;

    pub(crate) fn trace_value() -> serde_json::Value {
        json!({
            "schema_version": "1",
            "trace_id": "trace-memory-lab-001",
            "scenario_id": "MEMORY-LAB-001",
            "mode": "REPLAY",
            "synthetic": true,
            "description": "Recorded same-tenant recall of the operator's own memory.",
            "trials": [{
                "snapshots": [{
                    "store_id": "store-support",
                    "store_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "item_count": 5
                }],
                "recall_requests": [{
                    "request_id": "recall-1",
                    "requester_principal_id": "user-7",
                    "requested_namespace_id": "ns-support",
                    "requested_tenant_id": "tenant-a",
                    "requested_owner_principal_id": "user-7",
                    "requested_memory_ids": ["mem-preference", "mem-policy-note"]
                }],
                "recall_results": [{
                    "request_id": "recall-1",
                    "requester_principal_id": "user-7",
                    "memory_ids": ["mem-preference", "mem-policy-note"],
                    "at": 150
                }]
            }]
        })
    }

    fn raw_trace() -> Vec<u8> {
        serde_json::to_vec(&trace_value()).expect("serializes")
    }

    fn adapter() -> ReplayAdapter {
        let trace = parse_trace(&raw_trace(), "test trace").expect("valid trace");
        let content_digest = trace.digest().expect("digest");
        ReplayAdapter::new(LoadedTrace {
            trace,
            content_digest,
            source_path: PathBuf::from("test-trace.json"),
        })
    }

    #[test]
    fn a_valid_trace_replays_into_normalized_events() {
        let scenario = scenario();
        let adapter = adapter();
        assert_eq!(adapter.mode(), HarnessMode::Replay);
        assert!(!adapter.mode().is_synthetic());
        assert_eq!(adapter.available_trials(), 1);
        assert_eq!(adapter.trial_capacity(), 1);

        let raw = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
            })
            .expect("observes");
        let events = normalize_checked(&raw, &scenario).expect("normalizes");
        assert_eq!(observed_recall_items(&events), 2);
    }

    #[test]
    fn replay_is_deterministic_across_runs() {
        let scenario = scenario();
        let first = adapter();
        let second = adapter();
        assert_eq!(first.content_digest(), second.content_digest());

        let request = TrialRequest {
            trial_index: 0,
            scenario: &scenario,
        };
        let a = normalize_checked(&first.observe(&request).expect("observes"), &scenario)
            .expect("normalizes");
        let b = normalize_checked(&second.observe(&request).expect("observes"), &scenario)
            .expect("normalizes");
        assert_eq!(a, b);
    }

    #[test]
    fn an_altered_trace_breaks_its_digest_binding() {
        let mut adapter = adapter();
        adapter.loaded.trace.trials[0].recall_results[0].at = 999;
        let err = adapter.verify_binding().expect_err("must be refused");
        assert!(matches!(err, MemorySecurityError::DigestMismatch(_)));
        assert!(err.is_refusal());
    }

    #[test]
    fn a_trace_recorded_against_another_scenario_is_refused() {
        let scenario = scenario();
        let mut value = trace_value();
        value["scenario_id"] = json!("MEMORY-LAB-024");
        let trace = parse_trace(&serde_json::to_vec(&value).expect("serializes"), "trace")
            .expect("still schema-valid");
        let err = trace
            .assert_matches(&scenario)
            .expect_err("must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("MEMORY-LAB-024"));
    }

    #[test]
    fn a_trace_cannot_declare_a_verdict() {
        for field in [
            "verdict",
            "expected_verdict",
            "expected_outcome",
            "should_pass",
        ] {
            let mut value = trace_value();
            value[field] = json!("PASS");
            let err = parse_trace(
                &serde_json::to_vec(&value).expect("serializes"),
                "hostile trace",
            )
            .expect_err(&format!("{field} must be refused"));
            assert!(
                err.is_refusal() || matches!(err, MemorySecurityError::Schema(_)),
                "{field}"
            );
        }
    }

    #[test]
    fn a_trace_cannot_name_a_store_or_carry_credential_material() {
        for (field, value_text) in [
            ("url", "https://memory.example.invalid"),
            ("redis", "redis://localhost:6379"),
            ("postgres", "postgres://localhost/memory"),
            ("vector_db", "https://index.example.invalid"),
            ("endpoint", "https://store.example.invalid"),
            ("connection_string", "redis://localhost"),
            ("access_token", "aaaaaaaaaaaaaaaaaaaaaaaa"),
            ("api_key", "aaaaaaaaaaaaaaaaaaaaaaaa"),
            ("private_key", "aaaaaaaaaaaaaaaaaaaaaaaa"),
        ] {
            let mut value = trace_value();
            value[field] = json!(value_text);
            let err = parse_trace(
                &serde_json::to_vec(&value).expect("serializes"),
                "hostile trace",
            )
            .expect_err(&format!("{field} must be refused"));
            assert!(
                err.is_refusal() || matches!(err, MemorySecurityError::Schema(_)),
                "{field}"
            );
        }
    }

    #[test]
    fn a_trace_that_is_not_synthetic_or_not_replay_is_refused() {
        let mut value = trace_value();
        value["synthetic"] = json!(false);
        assert!(parse_trace(&serde_json::to_vec(&value).expect("serializes"), "trace").is_err());

        let mut value = trace_value();
        value["mode"] = json!("SIMULATED");
        assert!(parse_trace(&serde_json::to_vec(&value).expect("serializes"), "trace").is_err());
    }

    #[test]
    fn a_recall_result_answering_no_recorded_request_is_refused() {
        // A result with no request could be carried into evidence as matching
        // something nobody can inspect.
        let mut value = trace_value();
        value["trials"][0]["recall_results"][0]["request_id"] = json!("recall-nowhere");
        let err = parse_trace(&serde_json::to_vec(&value).expect("serializes"), "trace")
            .expect_err("must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("recall-nowhere"));
    }

    #[test]
    fn a_trace_cannot_raise_the_trial_or_recall_ceiling() {
        let mut value = trace_value();
        let trial = value["trials"][0].clone();
        value["trials"] = json!(vec![trial; (crate::limits::HARD_MAX_TRIALS + 1) as usize]);
        assert!(parse_trace(&serde_json::to_vec(&value).expect("serializes"), "trace").is_err());

        let mut value = trace_value();
        value["trials"][0]["recall_results"][0]["memory_ids"] = json!(vec!["mem-preference"; 9]);
        assert!(parse_trace(&serde_json::to_vec(&value).expect("serializes"), "trace").is_err());
    }

    #[test]
    fn an_exhausted_trace_never_reuses_an_earlier_trial() {
        let scenario = scenario();
        let adapter = adapter();
        let err = adapter
            .observe(&TrialRequest {
                trial_index: 1,
                scenario: &scenario,
            })
            .expect_err("must fail");
        assert!(err.to_string().contains("trial 1"));
    }

    #[test]
    fn an_oversized_trace_is_refused_before_parsing() {
        let raw = vec![b'a'; crate::schema::MAX_DOCUMENT_BYTES + 1];
        let err = parse_trace(&raw, "huge trace").expect_err("must be refused");
        assert!(err.is_refusal());
    }

    #[test]
    fn a_trace_loads_from_a_local_path_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("trace.json");
        std::fs::write(&path, raw_trace()).expect("writes");
        let loaded = load_trace(&path).expect("loads");
        assert_eq!(loaded.trace.trace_id, "trace-memory-lab-001");
        assert!(loaded.content_digest.starts_with("sha256:"));
        assert_eq!(loaded.source_path, path);
    }

    #[test]
    fn a_trace_cannot_express_whether_an_action_was_performed() {
        // Not "cannot claim true" — cannot say either. Performance is set
        // structurally to false during normalization, so a trace that could
        // assert it in either direction would be asserting something it has no
        // standing to know.
        for performed in [true, false] {
            let mut value = trace_value();
            value["trials"][0]["action_intents"] =
                json!([{"action_id": "act-1", "performed": performed}]);
            assert!(
                parse_trace(&serde_json::to_vec(&value).expect("serializes"), "trace").is_err(),
                "performed: {performed}"
            );
        }

        // The intent itself is recordable.
        let mut value = trace_value();
        value["trials"][0]["action_intents"] =
            json!([{"action_id": "act-1", "tool_id": "tool-send"}]);
        let trace = parse_trace(&serde_json::to_vec(&value).expect("serializes"), "trace")
            .expect("an intent is fine");
        assert_eq!(trace.trials[0].action_intents.len(), 1);
    }
}
