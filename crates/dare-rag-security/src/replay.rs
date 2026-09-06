//! The replay adapter: sanitized local traces, nothing else.
//!
//! A trace is a recording of a retrieval run. It is admitted only after a size
//! bound, a version check, the hostile sweep, its schema, a typed decode, a
//! scenario-identity check and a digest binding — in that order, so a hostile
//! value never reaches a validator that would quote it back.
//!
//! What a trace *cannot* do is the important part. It names objects by id; the
//! scenario's declared corpus supplies every binding. So a trace cannot assert
//! that a chunk belonged to a trusted document, that a returned document was
//! inside the acting tenant, or that a filter was satisfied. It can only say
//! what was returned, and the corpus decides what that means.
//!
//! It also cannot claim to be production evidence: `synthetic` is fixed to
//! `true` by the schema and re-checked here, and the result artifact reads that
//! flag from the trace rather than inferring it from the mode.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{RagSecurityError, Result};
use crate::harness::{HarnessAdapter, HarnessMode, RawTrialOutput, TrialRequest};
use crate::model::RagSecurityScenario;

/// A recorded retrieval run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagTrace {
    pub schema_version: String,
    pub trace_id: String,
    /// The scenario this trace was recorded against.
    pub scenario_id: String,
    /// Always `REPLAY`. A trace cannot ask to be run any other way.
    pub mode: HarnessMode,
    /// Always `true`. Cycle 017 traces are synthetic by construction.
    pub synthetic: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub trials: Vec<RawTrialOutput>,
}

impl RagTrace {
    /// Structural checks the schema cannot express.
    pub fn validate(&self) -> Result<()> {
        if self.mode != HarnessMode::Replay {
            return Err(RagSecurityError::refusal(format!(
                "trace `{}` declares mode `{}`; a recorded trace can only be replayed",
                self.trace_id,
                self.mode.as_str()
            )));
        }
        if !self.synthetic {
            // A trace claiming to be production evidence would let a report
            // present replayed observations as real-world retrieval validation.
            return Err(RagSecurityError::refusal(format!(
                "trace `{}` does not declare itself synthetic; Cycle 017 replays synthetic \
                 traces only",
                self.trace_id
            )));
        }
        crate::canonical::assert_safe_identifier(&self.trace_id, "trace id")?;
        crate::canonical::assert_safe_identifier(&self.scenario_id, "trace scenario id")?;

        if self.trials.is_empty() {
            return Err(RagSecurityError::invalid(format!(
                "trace `{}` records no trial",
                self.trace_id
            )));
        }
        if self.trials.len() as u32 > crate::limits::HARD_MAX_TRIALS {
            return Err(RagSecurityError::BudgetExhausted(format!(
                "trace `{}` records {} trials; the hard maximum is {}",
                self.trace_id,
                self.trials.len(),
                crate::limits::HARD_MAX_TRIALS
            )));
        }

        for (index, trial) in self.trials.iter().enumerate() {
            if trial.queries.len() as u32 > crate::limits::HARD_MAX_QUERIES_PER_TRIAL {
                return Err(RagSecurityError::BudgetExhausted(format!(
                    "trace `{}` trial {index} records {} queries; the hard maximum is {}",
                    self.trace_id,
                    trial.queries.len(),
                    crate::limits::HARD_MAX_QUERIES_PER_TRIAL
                )));
            }
            for set in &trial.result_sets {
                if set.results.len() as u32 > crate::limits::HARD_MAX_RESULTS_PER_QUERY {
                    return Err(RagSecurityError::BudgetExhausted(format!(
                        "trace `{}` trial {index} returns {} results for query `{}`; the hard \
                         maximum is {}",
                        self.trace_id,
                        set.results.len(),
                        set.query_id,
                        crate::limits::HARD_MAX_RESULTS_PER_QUERY
                    )));
                }
            }
            // A result set answering a query the same trial never recorded
            // cannot be inspected: nothing says what was asked for.
            let recorded: std::collections::BTreeSet<&str> = trial
                .queries
                .iter()
                .map(|query| query.query_id.as_str())
                .collect();
            for set in &trial.result_sets {
                if !recorded.contains(set.query_id.as_str()) {
                    return Err(RagSecurityError::invalid(format!(
                        "trace `{}` trial {index} returns results for query `{}`, which the same \
                         trial never recorded",
                        self.trace_id, set.query_id
                    )));
                }
            }
        }
        Ok(())
    }

    /// Refuse a trace recorded against a different scenario.
    pub fn assert_matches(&self, scenario: &RagSecurityScenario) -> Result<()> {
        if self.scenario_id != scenario.id {
            return Err(RagSecurityError::DigestMismatch(format!(
                "trace `{}` was recorded against scenario `{}` and cannot be replayed against \
                 `{}`",
                self.trace_id, self.scenario_id, scenario.id
            )));
        }
        Ok(())
    }
}

/// A trace that has passed every gate.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedTrace {
    pub trace: RagTrace,
    /// Digest of the document as it was read, so the artifact records exactly
    /// what was replayed.
    pub source_digest: String,
}

/// Parse a trace from bytes: size, version, hostile sweep, schema, decode.
pub fn parse_trace(raw: &[u8], label: &str) -> Result<LoadedTrace> {
    crate::schema::enforce_document_size(raw, label)?;
    let value: serde_json::Value = serde_json::from_slice(raw)
        .map_err(|err| RagSecurityError::schema(format!("{label} is not valid JSON: {err}")))?;
    crate::schema::validate_trace_document(&value)?;
    let trace: RagTrace = serde_json::from_value(value)?;
    trace.validate()?;

    let source_digest = crate::canonical::digest(&trace)?;
    Ok(LoadedTrace {
        trace,
        source_digest,
    })
}

/// Load a trace from a local path.
///
/// A path, not a URL: there is no code here that could fetch anything.
pub fn load_trace(path: &Path) -> Result<LoadedTrace> {
    let raw = std::fs::read(path).map_err(|err| {
        RagSecurityError::invalid(format!("trace unavailable ({}): {err}", path.display()))
    })?;
    parse_trace(&raw, "replay trace")
}

/// Replays a recorded trace and nothing else.
#[derive(Debug, Clone, PartialEq)]
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

    pub fn trace(&self) -> &RagTrace {
        &self.loaded.trace
    }

    pub fn source_digest(&self) -> &str {
        &self.loaded.source_digest
    }

    pub fn available_trials(&self) -> u32 {
        self.loaded.trace.trials.len() as u32
    }

    /// Verify the trace still digests to what was recorded at load time.
    pub fn verify_binding(&self) -> Result<()> {
        crate::canonical::verify_digest(
            &self.loaded.trace,
            &self.loaded.source_digest,
            "replay trace",
        )
    }
}

impl HarnessAdapter for ReplayAdapter {
    fn mode(&self) -> HarnessMode {
        HarnessMode::Replay
    }

    fn trial_capacity(&self) -> u32 {
        self.available_trials()
    }

    /// Answered from the loaded trace rather than from the mode.
    ///
    /// `validate` refuses any trace that does not declare itself synthetic, so
    /// this is always true in practice — but it is read from the document
    /// rather than hard-coded, so the artifact says what the trace said.
    fn observations_are_synthetic(&self) -> bool {
        self.loaded.trace.synthetic
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
                RagSecurityError::invalid(format!(
                    "trace `{}` records {} trials; trial {} was requested",
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
    use crate::model::ReferenceBehavior;
    use serde_json::json;

    pub(crate) fn trace_value() -> serde_json::Value {
        let scenario = scenario();
        let trials: Vec<RawTrialOutput> = (0..2)
            .map(|_| {
                crate::simulated::stage(&scenario, ReferenceBehavior::Compliant).expect("stages")
            })
            .collect();
        json!({
            "schema_version": "1",
            "trace_id": "trace-fixture",
            "scenario_id": scenario.id,
            "mode": "REPLAY",
            "synthetic": true,
            "description": "a locally recorded synthetic retrieval run",
            "trials": trials,
        })
    }

    pub(crate) fn adapter() -> ReplayAdapter {
        let raw = serde_json::to_vec(&trace_value()).expect("serializes");
        ReplayAdapter::new(parse_trace(&raw, "trace").expect("parses"))
    }

    #[test]
    fn a_well_formed_trace_parses_and_replays() {
        let adapter = adapter();
        assert_eq!(adapter.available_trials(), 2);
        assert_eq!(adapter.mode(), HarnessMode::Replay);

        let scenario = scenario();
        let output = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
            })
            .expect("replays");
        assert!(!output.result_sets.is_empty());
    }

    #[test]
    fn a_trace_can_never_declare_a_non_replay_mode() {
        let mut value = trace_value();
        value["mode"] = json!("SIMULATED");
        let raw = serde_json::to_vec(&value).expect("serializes");
        // The schema pins it, so this is refused before the typed check.
        assert!(parse_trace(&raw, "trace").is_err());
    }

    #[test]
    fn a_trace_claiming_production_evidence_is_refused() {
        let mut value = trace_value();
        value["synthetic"] = json!(false);
        let raw = serde_json::to_vec(&value).expect("serializes");
        assert!(parse_trace(&raw, "trace").is_err());
    }

    #[test]
    fn a_replayed_run_still_reports_its_observations_as_synthetic() {
        // The mode alone says "not staged", which is true and misleading. Every
        // trace Cycle 017 admits declares itself synthetic, and the artifact
        // must say so or a replayed run could be read as production evidence.
        let adapter = adapter();
        assert!(!adapter.mode().is_synthetic());
        assert!(adapter.observations_are_synthetic());
    }

    #[test]
    fn a_trace_recorded_against_another_scenario_is_refused() {
        let adapter = adapter();
        let mut other = scenario();
        other.id = "RAG-LAB-SOMETHING-ELSE".to_owned();
        let err = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &other,
            })
            .expect_err("must be refused");
        assert!(matches!(err, RagSecurityError::DigestMismatch(_)));
    }

    #[test]
    fn a_trace_cannot_assert_a_binding_the_corpus_disagrees_with() {
        // The central guarantee. A trace claims a chunk came from the handbook;
        // normalization records the corpus binding beside the claim, and the
        // mismatch is what a provenance finding is made of.
        let scenario = scenario();
        let mut value = trace_value();
        value["trials"][0]["result_sets"][0]["results"][0]["document_id"] = json!("doc-handbook");
        value["trials"][0]["result_sets"][0]["results"][0]["chunk_id"] =
            json!("chunk-doc-external");

        let raw = serde_json::to_vec(&value).expect("serializes");
        let adapter = ReplayAdapter::new(parse_trace(&raw, "trace").expect("parses"));
        let output = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
            })
            .expect("replays");
        let events = crate::harness::normalize_checked(&output, &scenario).expect("normalizes");

        let (claimed, bound) = events
            .iter()
            .find_map(|event| match event {
                crate::observation::RagObservationEvent::RetrievedChunk {
                    chunk_id,
                    claimed_document_id,
                    bound_document_id,
                    ..
                } if chunk_id == "chunk-doc-external" => {
                    Some((claimed_document_id.clone(), bound_document_id.clone()))
                }
                _ => None,
            })
            .expect("the chunk was recorded");
        assert_eq!(claimed, "doc-handbook");
        assert_eq!(bound, "doc-external", "the corpus binding won");
    }

    #[test]
    fn a_result_set_answering_an_unrecorded_query_is_refused() {
        // Nothing says what was asked for, so nothing can say whether the
        // answer was in bounds.
        let mut value = trace_value();
        value["trials"][0]["queries"] = json!([]);
        let raw = serde_json::to_vec(&value).expect("serializes");
        let err = parse_trace(&raw, "trace").expect_err("must be refused");
        assert!(err.to_string().contains("never recorded"));
    }

    #[test]
    fn an_over_bound_trace_is_refused() {
        let mut value = trace_value();
        let trial = value["trials"][0].clone();
        value["trials"] = json!((0..=crate::limits::HARD_MAX_TRIALS)
            .map(|_| trial.clone())
            .collect::<Vec<_>>());
        let raw = serde_json::to_vec(&value).expect("serializes");
        assert!(parse_trace(&raw, "trace").is_err());
    }

    #[test]
    fn asking_a_trace_for_a_trial_it_never_recorded_is_a_bounded_failure() {
        // Not an opportunity to reuse an earlier trial's observations.
        let adapter = adapter();
        let scenario = scenario();
        let err = adapter
            .observe(&TrialRequest {
                trial_index: 9,
                scenario: &scenario,
            })
            .expect_err("must fail");
        assert!(err.to_string().contains("records 2 trials"));
    }

    #[test]
    fn a_trace_carrying_a_credential_or_endpoint_is_refused() {
        for hostile in [
            json!({"api_key": "aaaaaaaaaaaaaaaaaaaaaaaa"}),
            json!({"description": "recorded from https://index.example.invalid"}),
            json!({"verdict": "PASS"}),
        ] {
            let mut value = trace_value();
            for (key, entry) in hostile.as_object().expect("object") {
                value[key] = entry.clone();
            }
            let raw = serde_json::to_vec(&value).expect("serializes");
            assert!(
                parse_trace(&raw, "trace").is_err(),
                "{hostile} was accepted"
            );
        }
    }

    #[test]
    fn the_binding_digest_catches_a_mutated_trace() {
        let mut adapter = adapter();
        adapter.loaded.trace.trials.clear();
        assert!(adapter.verify_binding().is_err());
    }

    #[test]
    fn an_oversized_trace_is_refused_before_it_is_parsed() {
        let raw = vec![b'a'; crate::schema::MAX_DOCUMENT_BYTES + 1];
        let err = parse_trace(&raw, "trace").expect_err("must be refused");
        assert!(err.is_refusal());
    }
}
