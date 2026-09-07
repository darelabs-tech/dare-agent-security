//! The replay adapter: sanitized local traces, nothing else.
//!
//! A trace is admitted only after a size bound, a version check, the hostile
//! sweep, its schema, a typed decode and a **semantic binding check** — in that
//! order, so a hostile value never reaches a validator that would quote it
//! back.
//!
//! The semantic binding is the part Cycle 017 got wrong. Matching `scenario_id`
//! is identity, not authority. A trace also carries the requests it observed,
//! and those fields decide protocol, routing and operation semantics. They must
//! agree with the approved scenario before any evaluator sees them, or a trace
//! could restate a request with wider semantics and have the widened version
//! judged as though it had been approved.
//!
//! A trace also cannot claim to be production evidence: `synthetic` is fixed to
//! `true` by the schema and re-checked here.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{McpAuthSecurityError, Result};
use crate::harness::{HarnessAdapter, HarnessMode, RawHarnessError, RawTrialOutput, TrialRequest};
use crate::model::McpAuthScenario;

/// A recorded MCP authorization run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpAuthTrace {
    pub schema_version: String,
    pub trace_id: String,
    pub scenario_id: String,
    /// Always `REPLAY`. A recording cannot ask to be run any other way.
    pub mode: HarnessMode,
    /// Always `true`.
    pub synthetic: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub trials: Vec<RawTrialOutput>,
}

impl McpAuthTrace {
    /// Structural checks the schema cannot express.
    pub fn validate(&self) -> Result<()> {
        if self.mode != HarnessMode::Replay {
            return Err(McpAuthSecurityError::refusal(format!(
                "trace `{}` declares mode `{}`; a recorded trace can only be replayed",
                self.trace_id,
                self.mode.as_str()
            )));
        }
        if !self.synthetic {
            return Err(McpAuthSecurityError::refusal(format!(
                "trace `{}` does not declare itself synthetic; Cycle 018 replays synthetic \
                 traces only",
                self.trace_id
            )));
        }
        crate::canonical::assert_safe_identifier(&self.trace_id, "trace id")?;
        crate::canonical::assert_safe_identifier(&self.scenario_id, "trace scenario id")?;

        if self.trials.is_empty() {
            return Err(McpAuthSecurityError::invalid(format!(
                "trace `{}` records no trial",
                self.trace_id
            )));
        }
        if self.trials.len() as u32 > crate::limits::HARD_MAX_TRIALS {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "trace `{}` records {} trials; the hard maximum is {}",
                self.trace_id,
                self.trials.len(),
                crate::limits::HARD_MAX_TRIALS
            )));
        }
        for (index, trial) in self.trials.iter().enumerate() {
            if trial.observed_requests.len() as u32 > crate::limits::HARD_MAX_REQUESTS_PER_TRIAL {
                return Err(McpAuthSecurityError::BudgetExhausted(format!(
                    "trace `{}` trial {index} records {} requests; the hard maximum is {}",
                    self.trace_id,
                    trial.observed_requests.len(),
                    crate::limits::HARD_MAX_REQUESTS_PER_TRIAL
                )));
            }
            for request in &trial.observed_requests {
                request.validate()?;
            }
        }
        Ok(())
    }

    /// Refuse a trace that is not semantically bound to the approved scenario.
    ///
    /// `scenario_id` is identity, not authority. The observed requests carry
    /// protocol and operation semantics that decide what the evaluator judges,
    /// so they must agree with the scenario on the authorization-relevant
    /// projection before any evaluator sees them.
    pub fn assert_matches(&self, scenario: &McpAuthScenario) -> Result<()> {
        if self.scenario_id != scenario.id {
            return Err(McpAuthSecurityError::DigestMismatch(format!(
                "trace `{}` was recorded against scenario `{}` and cannot be replayed against \
                 `{}`",
                self.trace_id, self.scenario_id, scenario.id
            )));
        }
        for trial in &self.trials {
            crate::harness::assert_requests_bound(trial, scenario)?;
        }
        Ok(())
    }
}

/// Parse and fully validate a trace document.
pub fn parse_trace(raw: &[u8], label: &str) -> Result<McpAuthTrace> {
    crate::schema::enforce_document_size(raw, label)?;
    let value: serde_json::Value = serde_json::from_slice(raw)
        .map_err(|err| McpAuthSecurityError::schema(format!("{label} is not valid JSON: {err}")))?;
    crate::schema::validate_trace_document(&value)?;
    let trace: McpAuthTrace = serde_json::from_value(value)?;
    trace.validate()?;
    Ok(trace)
}

/// Load a trace from disk.
pub fn load_trace(path: &Path) -> Result<McpAuthTrace> {
    let raw = std::fs::read(path)?;
    parse_trace(&raw, "trace")
}

/// Replays a validated trace. Opens nothing.
#[derive(Debug, Clone)]
pub struct ReplayAdapter {
    trace: McpAuthTrace,
}

impl ReplayAdapter {
    pub fn new(trace: McpAuthTrace) -> Self {
        Self { trace }
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        Ok(Self::new(load_trace(path)?))
    }

    pub fn trace(&self) -> &McpAuthTrace {
        &self.trace
    }
}

impl HarnessAdapter for ReplayAdapter {
    fn mode(&self) -> HarnessMode {
        HarnessMode::Replay
    }

    fn observe(&self, request: &TrialRequest<'_>) -> Result<RawTrialOutput> {
        match self.trace.trials.get(request.trial_index as usize) {
            Some(trial) => Ok(trial.clone()),
            // A bounded failure, not a panic and not a silent empty trial: an
            // empty trial would contribute nothing and look like a clean run.
            None => Ok(RawTrialOutput {
                harness_error: Some(RawHarnessError {
                    kind: crate::source::HarnessErrorKind::AdapterFailure,
                    detail: format!(
                        "the trace records no trial at index {}",
                        request.trial_index
                    ),
                }),
                ..RawTrialOutput::default()
            }),
        }
    }

    fn trial_capacity(&self) -> u32 {
        self.trace.trials.len() as u32
    }

    fn observations_are_synthetic(&self) -> bool {
        // Read from the trace rather than inferred from the mode. Every trace
        // this engine admits declares itself synthetic, and a report must not
        // present a replayed observation as production evidence.
        self.trace.synthetic
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::tests::scenario;
    use serde_json::json;

    fn trace_value() -> serde_json::Value {
        let requests = serde_json::to_value(&scenario().requests).expect("serializes");
        json!({
            "schema_version": "1",
            "trace_id": "trace-mcp-auth-lab-001",
            "scenario_id": "MCP-AUTH-LAB-001",
            "mode": "REPLAY",
            "synthetic": true,
            "description": "Sanitized synthetic replay, recorded locally.",
            "trials": [ { "observed_requests": requests } ]
        })
    }

    fn adapter_from(value: serde_json::Value) -> ReplayAdapter {
        let raw = serde_json::to_vec(&value).expect("serializes");
        ReplayAdapter::new(parse_trace(&raw, "trace").expect("parses"))
    }

    #[test]
    fn a_well_formed_trace_parses_and_replays() {
        let adapter = adapter_from(trace_value());
        adapter.trace().assert_matches(&scenario()).expect("bound");
        assert_eq!(adapter.mode(), HarnessMode::Replay);
        assert_eq!(adapter.trial_capacity(), 1);
    }

    #[test]
    fn a_replayed_observation_still_reports_as_synthetic() {
        let adapter = adapter_from(trace_value());
        assert!(!adapter.mode().is_synthetic());
        assert!(adapter.observations_are_synthetic());
    }

    #[test]
    fn a_trace_can_never_declare_a_non_replay_mode() {
        let mut value = trace_value();
        value["mode"] = json!("SIMULATED");
        let raw = serde_json::to_vec(&value).expect("serializes");
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
    fn a_trace_recorded_against_another_scenario_is_refused() {
        let mut value = trace_value();
        value["scenario_id"] = json!("MCP-AUTH-LAB-999");
        let err = adapter_from(value)
            .trace()
            .assert_matches(&scenario())
            .expect_err("must be refused");
        assert!(matches!(err, McpAuthSecurityError::DigestMismatch(_)));
    }

    #[test]
    fn a_trace_cannot_rewrite_the_protocol_revision_it_replays() {
        // The Cycle 017 defect, in this cycle's shape. Same scenario_id, wider
        // semantics: a legacy request relabelled current would have the modern
        // authorization invariants applied to it.
        let mut value = trace_value();
        value["trials"][0]["observed_requests"][0]["protocol"]["declared_revision"] =
            json!(crate::LEGACY_WIRE_REVISION);
        let err = adapter_from(value)
            .trace()
            .assert_matches(&scenario())
            .expect_err("must be refused");
        assert!(err.is_refusal());
    }

    #[test]
    fn a_trace_cannot_rewrite_the_operation_it_replays() {
        let mut value = trace_value();
        value["trials"][0]["observed_requests"][0]["operation"]["name"] = json!("delete-invoice");
        let err = adapter_from(value)
            .trace()
            .assert_matches(&scenario())
            .expect_err("must be refused");
        assert!(err.to_string().contains("operation semantics"));
    }

    #[test]
    fn a_trace_cannot_introduce_a_request_the_scenario_never_declared() {
        let mut value = trace_value();
        value["trials"][0]["observed_requests"][0]["request_id"] = json!("req-shadow");
        let err = adapter_from(value)
            .trace()
            .assert_matches(&scenario())
            .expect_err("must be refused");
        assert!(err.to_string().contains("does not declare"));
    }

    #[test]
    fn a_trace_may_still_vary_the_routing_metadata_it_recorded() {
        // Routing is what the binding invariants judge. Binding it would make
        // the invariants untestable through replay.
        let mut value = trace_value();
        value["trials"][0]["observed_requests"][0]["headers"]["method"] = json!("resources/read");
        adapter_from(value)
            .trace()
            .assert_matches(&scenario())
            .expect("routing stays free");
    }

    #[test]
    fn a_trace_carrying_a_credential_or_endpoint_is_refused() {
        for hostile in [
            json!({"access_token": "x"}),
            json!({"note": "https://as.example.com"}),
            json!({"callback": "run"}),
        ] {
            let mut value = trace_value();
            value["trials"][0]["observed_requests"][0]["headers"] = hostile;
            let raw = serde_json::to_vec(&value).expect("serializes");
            assert!(parse_trace(&raw, "trace").is_err());
        }
    }

    #[test]
    fn an_over_bound_trace_is_refused() {
        let mut value = trace_value();
        let trial = value["trials"][0].clone();
        value["trials"] = json!(vec![trial; (crate::limits::HARD_MAX_TRIALS + 1) as usize]);
        let raw = serde_json::to_vec(&value).expect("serializes");
        assert!(parse_trace(&raw, "trace").is_err());
    }

    #[test]
    fn asking_a_trace_for_a_trial_it_never_recorded_is_a_bounded_failure() {
        // Not a panic, and not a silent empty trial: an empty trial would
        // contribute nothing and look like a clean run.
        let adapter = adapter_from(trace_value());
        let base = scenario();
        let output = adapter
            .observe(&TrialRequest {
                trial_index: 5,
                scenario: &base,
            })
            .expect("returns");
        assert!(output.harness_error.is_some());
    }
}
