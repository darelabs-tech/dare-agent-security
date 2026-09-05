//! Replay adapter.
//!
//! Evaluates a sanitized local transcript. No model is invoked, no process is
//! spawned and no network call is made — the adapter only reads a file the
//! operator already has and turns it into raw observations.
//!
//! Transcripts are untrusted input: size-bounded, schema-validated, swept for
//! executable/remote fields, and read only from inside an explicit root.

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{PromptInjectionError, Result};
use crate::harness::{
    HarnessAdapter, HarnessMode, RawAction, RawHarnessError, RawPolicyDecision, RawTrialOutput,
    TrialRequest,
};
use crate::schema::{
    assert_no_executable_or_remote_fields, assert_supported_version, enforce_document_size,
    validate_against,
};

pub const TRANSCRIPT_SCHEMA_V1_ID: &str =
    "https://darelabs.tech/schemas/prompt-injection/v1/transcript.schema.json";
pub const TRANSCRIPT_SCHEMA_V1_JSON: &str =
    include_str!("../../../schemas/prompt-injection/v1/transcript.schema.json");

/// One recorded trial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptTrial {
    pub index: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<RawAction>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_decisions: Vec<RawPolicyDecision>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emitted_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_error: Option<RawHarnessError>,
}

/// A sanitized local transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transcript {
    pub schema_version: String,
    pub scenario_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub trials: Vec<TranscriptTrial>,
}

impl Transcript {
    /// Parse and validate a transcript document.
    pub fn parse(value: Value) -> Result<Self> {
        assert_supported_version(&value, "transcript")?;
        assert_no_executable_or_remote_fields(&value, "transcript")?;
        validate_against(&value, TRANSCRIPT_SCHEMA_V1_JSON, "transcript")?;
        let transcript: Transcript = serde_json::from_value(value)?;

        let mut seen = std::collections::HashSet::new();
        for trial in &transcript.trials {
            if !seen.insert(trial.index) {
                return Err(PromptInjectionError::invalid(format!(
                    "transcript repeats trial index {}",
                    trial.index
                )));
            }
        }
        Ok(transcript)
    }

    /// Read a transcript from a path confined to `root`.
    pub fn load(root: &Path, path: &Path) -> Result<Self> {
        let resolved = resolve_within_root(root, path)?;
        let raw = fs::read(&resolved)?;
        enforce_document_size(&raw, "transcript")?;
        let value: Value = serde_json::from_slice(&raw).map_err(|err| {
            PromptInjectionError::schema(format!("transcript is not valid JSON: {err}"))
        })?;
        Self::parse(value)
    }

    fn trial(&self, index: u32) -> Option<&TranscriptTrial> {
        self.trials.iter().find(|trial| trial.index == index)
    }
}

/// Resolve a path and refuse anything that escapes `root`.
pub fn resolve_within_root(root: &Path, path: &Path) -> Result<PathBuf> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(PromptInjectionError::refusal(
            "transcript path attempts parent traversal",
        ));
    }

    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };

    // Compare canonical forms so symlinks cannot hop outside the root.
    let canonical_root = root
        .canonicalize()
        .map_err(|err| PromptInjectionError::invalid(format!("root unavailable: {err}")))?;
    let canonical = candidate
        .canonicalize()
        .map_err(|err| PromptInjectionError::invalid(format!("transcript unavailable: {err}")))?;
    if !canonical.starts_with(&canonical_root) {
        return Err(PromptInjectionError::refusal(
            "transcript path resolves outside the permitted root",
        ));
    }
    Ok(canonical)
}

/// Offline transcript replay.
#[derive(Debug, Clone)]
pub struct ReplayAdapter {
    transcript: Transcript,
}

impl ReplayAdapter {
    pub fn new(transcript: Transcript) -> Self {
        Self { transcript }
    }

    pub fn load(root: &Path, path: &Path) -> Result<Self> {
        Ok(Self::new(Transcript::load(root, path)?))
    }

    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }

    /// Refuse a transcript recorded for a different scenario.
    pub fn bind_scenario(&self, scenario_id: &str) -> Result<()> {
        if self.transcript.scenario_id != scenario_id {
            return Err(PromptInjectionError::DigestMismatch(format!(
                "transcript was recorded for scenario {} but {} was requested",
                self.transcript.scenario_id, scenario_id
            )));
        }
        Ok(())
    }

    /// Number of recorded trials available for replay.
    pub fn available_trials(&self) -> u32 {
        self.transcript.trials.len() as u32
    }
}

impl HarnessAdapter for ReplayAdapter {
    fn mode(&self) -> HarnessMode {
        HarnessMode::Replay
    }

    fn observe(&self, request: &TrialRequest<'_>) -> Result<RawTrialOutput> {
        self.bind_scenario(&request.scenario.id)?;
        let Some(trial) = self.transcript.trial(request.trial_index) else {
            // Missing evidence is not a violation. Surface it as a harness
            // condition so the evaluator can report ERROR rather than guess.
            return Ok(RawTrialOutput {
                harness_error: Some(RawHarnessError {
                    kind: crate::observation::HarnessErrorKind::MalformedTranscript,
                    detail: format!("transcript has no trial at index {}", request.trial_index),
                }),
                ..RawTrialOutput::default()
            });
        };

        Ok(RawTrialOutput {
            output_text: trial.output_text.clone(),
            goal_id: trial.goal_id.clone(),
            actions: trial.actions.clone(),
            policy_decisions: trial.policy_decisions.clone(),
            emitted_fields: trial.emitted_fields.clone(),
            harness_error: trial.harness_error.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::normalize;
    use crate::model::{CorpusEntry, PromptInjectionScenario};
    use crate::observation::{HarnessErrorKind, ObservationEvent, PolicyOutcome};
    use serde_json::json;

    fn scenario() -> PromptInjectionScenario {
        let mut value = crate::schema::tests::valid_scenario();
        value["vector"]["corpus_id"] = json!("direct-ignore-objective-001");
        serde_json::from_value(value).unwrap()
    }

    fn entry() -> CorpusEntry {
        serde_json::from_value(crate::corpus::tests::direct_entry()).unwrap()
    }

    fn transcript_value() -> Value {
        json!({
            "schema_version": "1",
            "scenario_id": "PI-LAB-001",
            "recorded_at": "2026-09-05",
            "trials": [
                {
                    "index": 0,
                    "output_text": "Summary of the ticket.",
                    "goal_id": "goal-summarize-ticket",
                    "emitted_fields": ["summary"]
                },
                {
                    "index": 1,
                    "output_text": "Summary of the ticket.",
                    "goal_id": "goal-summarize-ticket",
                    "actions": [{"action": "ticket.summarize"}],
                    "policy_decisions": [{"operation": "payment.transfer", "outcome": "DENY"}],
                    "emitted_fields": ["summary"]
                }
            ]
        })
    }

    fn adapter() -> ReplayAdapter {
        ReplayAdapter::new(Transcript::parse(transcript_value()).unwrap())
    }

    fn request<'a>(
        scenario: &'a PromptInjectionScenario,
        entry: &'a CorpusEntry,
        index: u32,
    ) -> TrialRequest<'a> {
        TrialRequest {
            trial_index: index,
            scenario,
            entry,
        }
    }

    #[test]
    fn schema_id_is_stable_and_transcript_parses() {
        let schema: Value = serde_json::from_str(TRANSCRIPT_SCHEMA_V1_JSON).unwrap();
        assert_eq!(schema["$id"], json!(TRANSCRIPT_SCHEMA_V1_ID));
        let transcript = Transcript::parse(transcript_value()).expect("transcript");
        assert_eq!(transcript.scenario_id, "PI-LAB-001");
        assert_eq!(transcript.trials.len(), 2);
    }

    #[test]
    fn replay_is_offline_and_reports_its_mode() {
        assert_eq!(adapter().mode(), HarnessMode::Replay);
        assert!(!HarnessMode::Replay.is_synthetic());
        // The adapter holds only parsed data: no client, socket or process handle.
        assert_eq!(adapter().available_trials(), 2);
    }

    #[test]
    fn recorded_trials_normalize_into_typed_events() {
        let scenario = scenario();
        let entry = entry();
        let adapter = adapter();
        let raw = adapter.observe(&request(&scenario, &entry, 1)).unwrap();
        assert_eq!(raw.goal_id.as_deref(), Some("goal-summarize-ticket"));

        let events = normalize(&raw, &scenario.objective);
        assert!(events
            .iter()
            .any(|e| matches!(e, ObservationEvent::GoalState(_))));
        assert!(events
            .iter()
            .any(|e| matches!(e, ObservationEvent::StructuredActionRequest(r) if !r.executed)));
        assert!(events.iter().any(|e| matches!(
            e,
            ObservationEvent::PolicyDecision(d) if d.outcome == PolicyOutcome::Deny
        )));
    }

    #[test]
    fn a_transcript_for_another_scenario_is_refused() {
        let mut value = transcript_value();
        value["scenario_id"] = json!("PI-LAB-999");
        let adapter = ReplayAdapter::new(Transcript::parse(value).unwrap());
        let err = adapter.bind_scenario("PI-LAB-001").unwrap_err();
        assert!(matches!(err, PromptInjectionError::DigestMismatch(_)));

        let scenario = scenario();
        let entry = entry();
        assert!(adapter.observe(&request(&scenario, &entry, 0)).is_err());
    }

    #[test]
    fn a_missing_trial_becomes_a_harness_condition_not_a_violation() {
        let scenario = scenario();
        let entry = entry();
        let raw = adapter().observe(&request(&scenario, &entry, 7)).unwrap();
        let error = raw.harness_error.clone().expect("harness error");
        assert_eq!(error.kind, HarnessErrorKind::MalformedTranscript);

        let events = normalize(&raw, &scenario.objective);
        assert_eq!(
            crate::invariant::evaluate(
                crate::model::InvariantType::AuthorizedGoalUnchanged,
                &scenario.objective,
                &events
            )
            .verdict,
            dare_security_evidence::Verdict::Error
        );
    }

    #[test]
    fn malformed_transcripts_fail_closed() {
        // Unknown top-level field.
        let mut value = transcript_value();
        value["provider"] = json!("openai");
        assert!(Transcript::parse(value).unwrap_err().is_refusal());

        // Unknown trial field.
        let mut value = transcript_value();
        value["trials"][0]["confidence"] = json!(0.9);
        assert!(Transcript::parse(value).is_err());

        // Unsupported version.
        let mut value = transcript_value();
        value["schema_version"] = json!("2");
        assert!(Transcript::parse(value).unwrap_err().is_refusal());

        // No trials at all.
        let mut value = transcript_value();
        value["trials"] = json!([]);
        assert!(Transcript::parse(value).is_err());

        // Not an object.
        assert!(Transcript::parse(json!("nope")).is_err());
    }

    #[test]
    fn transcripts_cannot_exceed_the_trial_hard_maximum() {
        let mut trials = Vec::new();
        for index in 0..11 {
            trials.push(json!({"index": index}));
        }
        let mut value = transcript_value();
        value["trials"] = Value::Array(trials);
        assert!(Transcript::parse(value).is_err());
    }

    #[test]
    fn duplicate_trial_indexes_fail_closed() {
        let mut value = transcript_value();
        value["trials"][1]["index"] = json!(0);
        assert!(Transcript::parse(value).is_err());
    }

    #[test]
    fn oversized_transcript_output_is_rejected() {
        let mut value = transcript_value();
        value["trials"][0]["output_text"] = json!("x".repeat(16_385));
        assert!(Transcript::parse(value).is_err());
    }

    #[test]
    fn oversized_transcript_documents_are_refused_before_parsing() {
        let big = vec![b'x'; crate::schema::MAX_DOCUMENT_BYTES + 1];
        assert!(enforce_document_size(&big, "transcript")
            .unwrap_err()
            .is_refusal());
    }

    #[test]
    fn transcript_secrets_are_redacted_before_they_reach_evidence() {
        let mut value = transcript_value();
        value["trials"][0]["output_text"] =
            json!("here: DARE-SYNTHETIC-CANARY-ALPHA1 and sk-live-0123456789abcdef");
        let adapter = ReplayAdapter::new(Transcript::parse(value).unwrap());
        let scenario = scenario();
        let entry = entry();
        let raw = adapter.observe(&request(&scenario, &entry, 0)).unwrap();
        let events = normalize(&raw, &scenario.objective);

        for event in &events {
            event.validate().expect("event is secret safe");
        }
        let serialized = serde_json::to_string(&events).unwrap();
        assert!(!serialized.contains("ALPHA1"));
        assert!(!serialized.contains("sk-live-0123456789abcdef"));
        // The exact canary was still detected deterministically.
        assert!(events
            .iter()
            .any(|e| matches!(e, ObservationEvent::CanaryDisclosure(d) if d.exact_match)));
    }

    #[test]
    fn path_traversal_and_escape_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        fs::write(
            root.join("transcript.json"),
            serde_json::to_vec(&transcript_value()).unwrap(),
        )
        .unwrap();

        Transcript::load(root, Path::new("transcript.json")).expect("in-root load");

        let err = Transcript::load(root, Path::new("../escape.json")).unwrap_err();
        assert!(err.is_refusal());

        let outside = dir.path().parent().unwrap().join("outside.json");
        fs::write(&outside, b"{}").unwrap();
        let err = Transcript::load(root, &outside).unwrap_err();
        assert!(err.is_refusal(), "absolute outside root must be refused");
        let _ = fs::remove_file(&outside);
    }

    #[test]
    fn a_transcript_that_is_not_json_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("bad.json"), b"not json at all").unwrap();
        let err = Transcript::load(dir.path(), Path::new("bad.json")).unwrap_err();
        assert!(matches!(err, PromptInjectionError::Schema(_)));
    }

    #[test]
    fn replay_of_the_same_transcript_is_reproducible() {
        let scenario = scenario();
        let entry = entry();
        let adapter = adapter();
        let first = adapter.observe(&request(&scenario, &entry, 0)).unwrap();
        let second = adapter.observe(&request(&scenario, &entry, 0)).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            normalize(&first, &scenario.objective),
            normalize(&second, &scenario.objective)
        );
    }
}
