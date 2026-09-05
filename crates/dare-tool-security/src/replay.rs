//! Replay adapter.
//!
//! Evaluates a sanitized local trace. No tool is invoked, no MCP server is
//! contacted, no model is called, no process is spawned and no network I/O
//! happens — the adapter reads a file the operator already has and turns it
//! into raw observations.
//!
//! A trace is untrusted input, and is treated as such: size-bounded,
//! schema-validated, swept for executable/remote/expected-verdict fields, read
//! only from inside an explicit root, and bound to the scenario it was recorded
//! for.

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Result, ToolSecurityError};
use crate::harness::{
    assert_surface_claim_consistent, RawArguments, RawHarnessError, RawObjectiveState, RawOutput,
    RawPolicyDecision, RawRequest, RawSelection, RawToolSurface, RawToolTrialOutput,
    ToolHarnessAdapter, ToolHarnessMode, ToolTrialRequest,
};
use crate::observation::HarnessErrorKind;
use crate::schema::{
    assert_no_hostile_fields, assert_supported_version, enforce_document_size, validate_against,
};

pub const TRACE_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/tool-security/v1/trace.schema.json";
pub const TRACE_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/tool-security/v1/trace.schema.json");

/// One recorded trial.
///
/// The fields mirror [`RawToolTrialOutput`] exactly. They are spelled out
/// rather than flattened so `deny_unknown_fields` still applies — a flattened
/// struct would silently accept anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTraceTrial {
    pub index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_observed: Option<RawToolSurface>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective_state: Option<RawObjectiveState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selections: Vec<RawSelection>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requests: Vec<RawRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<RawArguments>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<RawOutput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain_steps: Vec<crate::harness::RawChainStep>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_decisions: Vec<RawPolicyDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_error: Option<RawHarnessError>,
}

impl ToolTraceTrial {
    /// Raw observations for this trial, without the index.
    pub fn observation(&self) -> RawToolTrialOutput {
        RawToolTrialOutput {
            surface_observed: self.surface_observed.clone(),
            objective_state: self.objective_state.clone(),
            selections: self.selections.clone(),
            requests: self.requests.clone(),
            arguments: self.arguments.clone(),
            outputs: self.outputs.clone(),
            chain_steps: self.chain_steps.clone(),
            policy_decisions: self.policy_decisions.clone(),
            harness_error: self.harness_error.clone(),
        }
    }
}

/// A sanitized local trace of tool-surface and tool-use behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTrace {
    pub schema_version: String,
    pub scenario_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub trials: Vec<ToolTraceTrial>,
}

impl ToolTrace {
    /// Parse and validate a trace document.
    ///
    /// Four independent gates run in order: version, hostile-field sweep, JSON
    /// Schema, and the typed layer with `deny_unknown_fields`. Each is capable
    /// of refusing on its own.
    pub fn parse(value: Value) -> Result<Self> {
        assert_supported_version(&value, "trace")?;
        assert_no_hostile_fields(&value, "trace")?;
        validate_against(&value, TRACE_SCHEMA_V1_JSON, "trace")?;
        let trace: ToolTrace = serde_json::from_value(value)?;

        let mut seen = HashSet::new();
        for trial in &trace.trials {
            if !seen.insert(trial.index) {
                return Err(ToolSecurityError::invalid(format!(
                    "trace repeats trial index {}",
                    trial.index
                )));
            }
        }

        if trace.trials.len() as u32 > crate::limits::HARD_MAX_TRIALS {
            return Err(ToolSecurityError::refusal(format!(
                "trace records {} trials, above the hard maximum {}",
                trace.trials.len(),
                crate::limits::HARD_MAX_TRIALS
            )));
        }

        Ok(trace)
    }

    /// Read a trace from a path confined to `root`.
    pub fn load(root: &Path, path: &Path) -> Result<Self> {
        let resolved = resolve_within_root(root, path)?;
        let raw = fs::read(&resolved)
            .map_err(|err| ToolSecurityError::invalid(format!("trace unreadable: {err}")))?;
        enforce_document_size(&raw, "trace")?;
        let value: Value = serde_json::from_slice(&raw)
            .map_err(|err| ToolSecurityError::schema(format!("trace is not valid JSON: {err}")))?;
        Self::parse(value)
    }

    fn trial(&self, index: u32) -> Option<&ToolTraceTrial> {
        self.trials.iter().find(|trial| trial.index == index)
    }
}

/// Resolve a path and refuse anything that escapes `root`.
///
/// Both the literal path and its canonical form are checked, so neither `..`
/// nor a symlink can hop outside the permitted root.
pub fn resolve_within_root(root: &Path, path: &Path) -> Result<PathBuf> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ToolSecurityError::refusal(
            "trace path attempts parent traversal",
        ));
    }

    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };

    let canonical_root = root
        .canonicalize()
        .map_err(|err| ToolSecurityError::invalid(format!("trace root unavailable: {err}")))?;
    let canonical = candidate
        .canonicalize()
        .map_err(|err| ToolSecurityError::invalid(format!("trace unavailable: {err}")))?;
    if !canonical.starts_with(&canonical_root) {
        return Err(ToolSecurityError::refusal(
            "trace path resolves outside the permitted root",
        ));
    }
    Ok(canonical)
}

/// Offline trace replay.
#[derive(Debug, Clone)]
pub struct ToolReplayAdapter {
    trace: ToolTrace,
}

impl ToolReplayAdapter {
    pub fn new(trace: ToolTrace) -> Self {
        Self { trace }
    }

    pub fn load(root: &Path, path: &Path) -> Result<Self> {
        Ok(Self::new(ToolTrace::load(root, path)?))
    }

    pub fn trace(&self) -> &ToolTrace {
        &self.trace
    }

    /// Refuse a trace recorded for a different scenario.
    pub fn bind_scenario(&self, scenario_id: &str) -> Result<()> {
        if self.trace.scenario_id != scenario_id {
            return Err(ToolSecurityError::DigestMismatch(format!(
                "trace was recorded for scenario {} but {scenario_id} was requested",
                self.trace.scenario_id
            )));
        }
        Ok(())
    }

    /// Number of recorded trials available for replay.
    pub fn available_trials(&self) -> u32 {
        self.trace.trials.len() as u32
    }
}

impl ToolHarnessAdapter for ToolReplayAdapter {
    fn mode(&self) -> ToolHarnessMode {
        ToolHarnessMode::Replay
    }

    fn observe(&self, request: &ToolTrialRequest<'_>) -> Result<RawToolTrialOutput> {
        self.bind_scenario(&request.scenario.id)?;

        let Some(trial) = self.trace.trial(request.trial_index) else {
            // A missing recording is not a violation. It surfaces as a harness
            // condition so the evaluator reports ERROR instead of guessing.
            return Ok(RawToolTrialOutput {
                harness_error: Some(RawHarnessError {
                    kind: HarnessErrorKind::MalformedTrace,
                    detail: format!("trace has no trial at index {}", request.trial_index),
                }),
                ..RawToolTrialOutput::default()
            });
        };

        if let Some(surface) = &trial.surface_observed {
            assert_surface_claim_consistent(surface, request.binding)?;
        }

        Ok(trial.observation())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::ToolIdentityBinding;
    use crate::harness::{normalize_checked, tests::binding, tests::scenario};
    use crate::model::ToolSecurityScenario;
    use crate::observation::{OutputTreatment, PolicyOutcome, ToolObservationEvent};
    use serde_json::json;

    fn trace_value() -> Value {
        json!({
            "schema_version": "1",
            "scenario_id": "TOOL-LAB-001",
            "recorded_at": "2026-09-05",
            "trials": [
                {
                    "index": 0,
                    "surface_observed": {
                        "surface_id": "support-desk-tools",
                        "digest_matches_approved": true,
                        "tool_ids": ["ticket_search", "ticket_summarize"]
                    },
                    "objective_state": {
                        "objective_id": "objective-support-summary",
                        "goal_id": "goal-summarize-ticket"
                    },
                    "selections": [{"tool_id": "ticket_search"}],
                    "requests": [{"tool_id": "ticket_search", "operation_class": "SEARCH"}],
                    "arguments": [{
                        "tool_id": "ticket_search",
                        "values": [{"name": "query", "value": "ticket 42"}]
                    }],
                    "outputs": [{
                        "tool_id": "ticket_search",
                        "content": "Ticket 42 is open.",
                        "treatment": "TREATED_AS_DATA"
                    }],
                    "chain_steps": [
                        {"tool_id": "ticket_search", "position": 0, "depth": 1}
                    ],
                    "policy_decisions": [
                        {"operation": "ticket.delete", "outcome": "DENY"}
                    ]
                },
                {
                    "index": 1,
                    "harness_error": {"kind": "TIMEOUT", "detail": "recorder timed out"}
                }
            ]
        })
    }

    fn adapter() -> ToolReplayAdapter {
        ToolReplayAdapter::new(ToolTrace::parse(trace_value()).unwrap())
    }

    fn request<'a>(
        index: u32,
        scenario: &'a ToolSecurityScenario,
        binding: &'a ToolIdentityBinding,
    ) -> ToolTrialRequest<'a> {
        ToolTrialRequest {
            trial_index: index,
            scenario,
            binding,
            entry: None,
        }
    }

    #[test]
    fn a_recorded_trial_replays_into_normalized_events() {
        let scenario = scenario();
        let binding = binding();
        let adapter = adapter();
        assert_eq!(adapter.mode(), ToolHarnessMode::Replay);
        assert_eq!(adapter.available_trials(), 2);

        let raw = adapter.observe(&request(0, &scenario, &binding)).unwrap();
        let events = normalize_checked(&raw, &binding).unwrap();
        assert_eq!(
            events
                .iter()
                .map(ToolObservationEvent::kind)
                .collect::<Vec<_>>(),
            [
                "TOOL_SURFACE_OBSERVED",
                "OBJECTIVE_STATE",
                "TOOL_SELECTED",
                "TOOL_REQUESTED",
                "TOOL_ARGUMENTS",
                "TOOL_OUTPUT_OBSERVED",
                "TOOL_CHAIN_STEP",
                "POLICY_DECISION"
            ]
        );
    }

    #[test]
    fn replay_is_deterministic_across_runs() {
        let scenario = scenario();
        let binding = binding();
        let first = adapter().observe(&request(0, &scenario, &binding)).unwrap();
        let second = adapter().observe(&request(0, &scenario, &binding)).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            normalize_checked(&first, &binding).unwrap(),
            normalize_checked(&second, &binding).unwrap()
        );
    }

    #[test]
    fn a_recorded_harness_error_replays_as_a_harness_condition() {
        let scenario = scenario();
        let binding = binding();
        let raw = adapter().observe(&request(1, &scenario, &binding)).unwrap();
        let events = normalize_checked(&raw, &binding).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].is_harness_error());
    }

    #[test]
    fn a_missing_trial_is_a_harness_condition_not_a_pass() {
        let scenario = scenario();
        let binding = binding();
        let raw = adapter().observe(&request(7, &scenario, &binding)).unwrap();
        let error = raw
            .harness_error
            .clone()
            .expect("missing trial must be reported");
        assert_eq!(error.kind, HarnessErrorKind::MalformedTrace);
        // And nothing behavioral is invented to fill the gap.
        assert_eq!(
            raw,
            RawToolTrialOutput {
                harness_error: Some(error),
                ..RawToolTrialOutput::default()
            }
        );
    }

    #[test]
    fn a_trace_recorded_for_another_scenario_is_refused() {
        let mut value = trace_value();
        value["scenario_id"] = json!("TOOL-LAB-009");
        let adapter = ToolReplayAdapter::new(ToolTrace::parse(value).unwrap());
        let scenario = scenario();
        let binding = binding();
        let err = adapter
            .observe(&request(0, &scenario, &binding))
            .unwrap_err();
        assert!(matches!(err, ToolSecurityError::DigestMismatch(_)));
    }

    #[test]
    fn a_self_contradicting_surface_record_is_refused_at_replay() {
        let binding = binding();
        let mut value = trace_value();
        value["trials"][0]["surface_observed"]["surface_digest"] =
            json!(binding.surface_digest.clone());
        value["trials"][0]["surface_observed"]["digest_matches_approved"] = json!(false);
        let adapter = ToolReplayAdapter::new(ToolTrace::parse(value).unwrap());
        let scenario = scenario();
        assert!(adapter.observe(&request(0, &scenario, &binding)).is_err());
    }

    #[test]
    fn executable_remote_and_verdict_fields_are_refused_at_any_depth() {
        for (pointer, value) in [
            ("/trials/0/shell", json!("rm -rf /")),
            ("/trials/0/command", json!("curl")),
            ("/trials/0/callback", json!("http://example.invalid")),
            ("/trials/0/mcp_server", json!("http://example.invalid")),
            ("/trials/0/endpoint", json!("https://example.invalid")),
            ("/trials/0/api_key", json!("sk-live-x")),
            ("/trials/0/expected_verdict", json!("PASS")),
            ("/trials/0/should_fail", json!(true)),
        ] {
            let mut trace = trace_value();
            let field = pointer.rsplit('/').next().unwrap();
            trace["trials"][0][field] = value;
            let err = ToolTrace::parse(trace).unwrap_err();
            assert!(
                err.is_refusal() || matches!(err, ToolSecurityError::Schema(_)),
                "{field} must be refused, got {err}"
            );
        }
    }

    #[test]
    fn a_trace_cannot_claim_a_request_was_dispatched() {
        let mut trace = trace_value();
        trace["trials"][0]["requests"][0]["dispatched"] = json!(true);
        assert!(ToolTrace::parse(trace).is_err());
    }

    #[test]
    fn duplicate_and_over_limit_trial_indices_fail_closed() {
        let mut trace = trace_value();
        trace["trials"][1] = trace["trials"][0].clone();
        let err = ToolTrace::parse(trace).unwrap_err();
        assert!(err.to_string().contains("repeats trial index"));

        let mut trace = trace_value();
        let template = trace["trials"][0].clone();
        let mut trials = Vec::new();
        for index in 0..11 {
            let mut trial = template.clone();
            trial["index"] = json!(index);
            trials.push(trial);
        }
        trace["trials"] = json!(trials);
        // The schema caps the array before the typed layer sees it.
        assert!(ToolTrace::parse(trace).is_err());
    }

    #[test]
    fn an_unknown_schema_version_or_enum_fails_closed() {
        let mut trace = trace_value();
        trace["schema_version"] = json!("2");
        assert!(ToolTrace::parse(trace).is_err());

        let mut trace = trace_value();
        trace["trials"][0]["outputs"][0]["treatment"] = json!("TREATED_AS_TRUSTED");
        assert!(ToolTrace::parse(trace).is_err());

        let mut trace = trace_value();
        trace["trials"][0]["policy_decisions"][0]["outcome"] = json!("MAYBE");
        assert!(ToolTrace::parse(trace).is_err());
    }

    #[test]
    fn recorded_enums_decode_to_the_typed_values() {
        let trace = ToolTrace::parse(trace_value()).unwrap();
        let trial = &trace.trials[0];
        assert_eq!(
            trial.outputs[0].treatment,
            OutputTreatment::TreatedAsData,
            "treatment is a recorded fact, decoded exactly"
        );
        assert_eq!(trial.policy_decisions[0].outcome, PolicyOutcome::Deny);
    }

    #[test]
    fn a_trace_path_cannot_escape_its_root() {
        let root = std::env::temp_dir().join("dare-tool-security-replay-root");
        let nested = root.join("traces");
        fs::create_dir_all(&nested).unwrap();
        let file = nested.join("trace.json");
        fs::write(&file, serde_json::to_vec(&trace_value()).unwrap()).unwrap();

        let trace = ToolTrace::load(&root, Path::new("traces/trace.json")).unwrap();
        assert_eq!(trace.scenario_id, "TOOL-LAB-001");

        for escape in [
            Path::new("../trace.json"),
            Path::new("traces/../../trace.json"),
        ] {
            let err = resolve_within_root(&root, escape).unwrap_err();
            assert!(err.is_refusal(), "{escape:?} must be refused");
        }

        // An absolute path outside the root is refused even without any `..`.
        let outside = std::env::temp_dir().join("dare-tool-security-outside.json");
        fs::write(&outside, b"{}").unwrap();
        let err = resolve_within_root(&root, &outside).unwrap_err();
        assert!(err.is_refusal());

        fs::remove_dir_all(&root).ok();
        fs::remove_file(&outside).ok();
    }

    #[test]
    fn an_oversized_trace_is_refused_before_it_is_parsed() {
        let root = std::env::temp_dir().join("dare-tool-security-replay-big");
        fs::create_dir_all(&root).unwrap();
        let file = root.join("big.json");
        let mut value = trace_value();
        value["note"] = json!("x".repeat(crate::schema::MAX_DOCUMENT_BYTES));
        fs::write(&file, serde_json::to_vec(&value).unwrap()).unwrap();

        let err = ToolTrace::load(&root, Path::new("big.json")).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "got {err}");

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn the_schema_id_and_version_are_stable() {
        let schema: Value = serde_json::from_str(TRACE_SCHEMA_V1_JSON).unwrap();
        assert_eq!(schema["$id"], json!(TRACE_SCHEMA_V1_ID));
        assert_eq!(schema["properties"]["schema_version"]["const"], json!("1"));
        assert_eq!(schema["additionalProperties"], json!(false));
    }
}
