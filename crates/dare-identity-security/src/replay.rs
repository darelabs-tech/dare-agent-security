//! Replay adapter: evaluate a sanitized local identity/authorization trace.
//!
//! Replay reads a file and decides nothing. It contacts no identity provider,
//! authorization server, PDP or resource, spawns no process, and performs none
//! of the operations the trace describes. Those are not policies applied at run
//! time — this module has no I/O beyond reading the trace path it was handed,
//! and [`ReplayTrace`] has no field that could name a remote endpoint.
//!
//! A trace is admitted only when it survives, in order: a size bound, a version
//! check, the hostile-field sweep, its JSON Schema, `deny_unknown_fields`
//! decoding, a scenario-identity check and a canonical digest binding. The
//! digest is what makes replay reproducible rather than merely repeatable: the
//! same trace bytes always yield the same events, and altered bytes are visible
//! as a different digest.
//!
//! A trace carries observations, never a verdict. There is deliberately no way
//! for a recorded trace to state the outcome it wants; that field is refused by
//! the hostile-field sweep and has no home in these types.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::canonical::digest;
use crate::error::{IdentitySecurityError, Result};
use crate::harness::{HarnessAdapter, HarnessMode, RawTrialOutput, TrialRequest};
use crate::model::IdentitySecurityScenario;
use crate::schema::{enforce_document_size, validate_trace_document};

/// A sanitized, previously recorded, local identity/authorization trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayTrace {
    pub schema_version: String,
    pub trace_id: String,
    /// The scenario this trace was recorded against.
    pub scenario_id: String,
    /// Always `REPLAY`. A trace cannot ask to be run any other way.
    pub mode: HarnessMode,
    /// Always `true`. Cycle 015 traces are synthetic by construction.
    pub synthetic: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub trials: Vec<RawTrialOutput>,
}

impl ReplayTrace {
    /// Structural checks the schema cannot express.
    pub fn validate(&self) -> Result<()> {
        if self.mode != HarnessMode::Replay {
            return Err(IdentitySecurityError::refusal(format!(
                "trace `{}` declares mode `{}`; a recorded trace can only be replayed",
                self.trace_id,
                self.mode.as_str()
            )));
        }
        if !self.synthetic {
            // A trace claiming to be production evidence would let a report
            // present replayed observations as real-world identity validation.
            return Err(IdentitySecurityError::refusal(format!(
                "trace `{}` does not declare itself synthetic; Cycle 015 replays synthetic \
                 traces only",
                self.trace_id
            )));
        }
        if self.trials.is_empty() {
            return Err(IdentitySecurityError::invalid(format!(
                "trace `{}` contains no trials",
                self.trace_id
            )));
        }
        if self.trials.len() as u32 > crate::limits::HARD_MAX_TRIALS {
            return Err(IdentitySecurityError::BudgetExhausted(format!(
                "trace `{}` carries {} trials; the hard maximum is {}",
                self.trace_id,
                self.trials.len(),
                crate::limits::HARD_MAX_TRIALS
            )));
        }
        Ok(())
    }

    /// Refuse a trace recorded against a different scenario.
    ///
    /// Without this, a trace of a permissive scenario could supply the passing
    /// observations for a stricter one.
    pub fn assert_matches(&self, scenario: &IdentitySecurityScenario) -> Result<()> {
        if self.scenario_id != scenario.id {
            return Err(IdentitySecurityError::refusal(format!(
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
    pub trace: ReplayTrace,
    /// Canonical digest of the decoded trace.
    pub content_digest: String,
    pub source_path: PathBuf,
}

/// Parse and validate a trace from raw bytes.
pub fn parse_trace(raw: &[u8], label: &str) -> Result<ReplayTrace> {
    enforce_document_size(raw, label)?;
    let value: serde_json::Value = serde_json::from_slice(raw)?;
    // Schema first, then the typed decode: two independent gates, so a field
    // slipping past one still has to survive the other.
    validate_trace_document(&value)?;
    let trace: ReplayTrace = serde_json::from_value(value)?;
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

    pub fn trace(&self) -> &ReplayTrace {
        &self.loaded.trace
    }

    pub fn content_digest(&self) -> &str {
        &self.loaded.content_digest
    }

    pub fn source_path(&self) -> &Path {
        &self.loaded.source_path
    }

    /// How many trials the trace can supply.
    pub fn available_trials(&self) -> u32 {
        self.loaded.trace.trials.len() as u32
    }

    /// Re-verify that the loaded trace still hashes to what it did at load.
    pub fn verify_binding(&self) -> Result<()> {
        let actual = self.loaded.trace.digest()?;
        if actual != self.loaded.content_digest {
            return Err(IdentitySecurityError::DigestMismatch(format!(
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

    fn observe(&self, request: &TrialRequest<'_>) -> Result<RawTrialOutput> {
        self.loaded.trace.assert_matches(request.scenario)?;
        self.verify_binding()?;
        let index = request.trial_index as usize;
        self.loaded
            .trace
            .trials
            .get(index)
            .cloned()
            // A trace that has run out of trials is a bounded failure, not an
            // opportunity to reuse an earlier trial's observations.
            .ok_or_else(|| {
                IdentitySecurityError::invalid(format!(
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
    use crate::harness::{normalize_checked, observed_operations};
    use crate::observation::IdentityObservationEvent;
    use serde_json::json;

    pub(crate) fn trace_value() -> serde_json::Value {
        json!({
            "schema_version": "1",
            "trace_id": "trace-identity-lab-001",
            "scenario_id": "IDENTITY-LAB-001",
            "mode": "REPLAY",
            "synthetic": true,
            "description": "Recorded on-behalf-of read within the delegated ceiling.",
            "trials": [{
                "principals": [
                    {"role": "INITIATING", "principal_id": "user-7", "kind": "HUMAN",
                     "tenant_id": "tenant-a"},
                    {"role": "EFFECTIVE", "principal_id": "user-7", "kind": "HUMAN",
                     "tenant_id": "tenant-a"},
                    {"role": "AGENT", "principal_id": "agent-1", "kind": "AGENT"}
                ],
                "effective_authorities": [
                    {"principal_id": "user-7", "authority_id": "authority-agent-read",
                     "source_ceiling_id": "authority-user-read"}
                ],
                "delegation_edges": [
                    {"edge_id": "edge-user-to-agent", "kind": "ON_BEHALF_OF",
                     "delegator_principal_id": "user-7", "delegatee_principal_id": "agent-1",
                     "delegated_subject_id": "user-7",
                     "authority_ceiling_id": "authority-agent-read"}
                ],
                "resources": [{
                    "resource_id": "document-123", "resource_type": "document",
                    "tenant_id": "tenant-a", "owner_principal_id": "user-7",
                    "classification": "SYNTHETIC_INTERNAL"
                }],
                "authorization_decisions": [{
                    "decision_id": "decision-1", "effect": "PERMIT", "subject_id": "user-7",
                    "policy_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "bound_operation_id": "op-1", "issued_at": 150
                }],
                "final_operations": [{
                    "operation_id": "op-1", "subject_id": "user-7", "action": "read",
                    "resource_id": "document-123", "resource_type": "document",
                    "tenant_id": "tenant-a", "objective_id": "objective-summarize-ticket"
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
        assert_eq!(adapter.available_trials(), 1);

        let raw = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &scenario,
            })
            .expect("observes");
        let events = normalize_checked(&raw, &scenario).expect("normalizes");
        assert_eq!(observed_operations(&events), 1);
        assert!(events
            .iter()
            .all(|event| !matches!(event, IdentityObservationEvent::HarnessError(_))));
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
        assert_eq!(
            serde_json::to_string(&a).expect("serializes"),
            serde_json::to_string(&b).expect("serializes")
        );
    }

    #[test]
    fn an_altered_trace_breaks_its_digest_binding() {
        let mut adapter = adapter();
        adapter.loaded.trace.trials[0].final_operations[0].resource_id = "document-999".to_owned();
        let err = adapter.verify_binding().expect_err("must be refused");
        assert!(matches!(err, IdentitySecurityError::DigestMismatch(_)));
        assert!(err.is_refusal());
    }

    #[test]
    fn a_trace_recorded_against_another_scenario_is_refused() {
        let scenario = scenario();
        let mut value = trace_value();
        value["scenario_id"] = json!("IDENTITY-LAB-024");
        let trace = parse_trace(&serde_json::to_vec(&value).expect("serializes"), "trace")
            .expect("still schema-valid");
        let err = trace
            .assert_matches(&scenario)
            .expect_err("must be refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("IDENTITY-LAB-024"));
    }

    #[test]
    fn a_trace_cannot_declare_a_verdict() {
        // Replay evaluates observations. A trace that could state its own
        // outcome would make the evaluator ceremonial.
        for field in ["verdict", "expected_verdict", "expected_outcome", "result"] {
            let mut value = trace_value();
            value[field] = json!("PASS");
            let err = parse_trace(
                &serde_json::to_vec(&value).expect("serializes"),
                "hostile trace",
            )
            .expect_err(&format!("{field} must be refused"));
            assert!(
                err.is_refusal() || matches!(err, IdentitySecurityError::Schema(_)),
                "{field}"
            );
        }
    }

    #[test]
    fn a_trace_cannot_name_a_remote_target_or_carry_credential_material() {
        for (field, value_text) in [
            ("url", "https://idp.example.invalid/token"),
            ("endpoint", "https://pdp.example.invalid"),
            ("issuer", "https://issuer.example.invalid"),
            ("jwks_uri", "https://issuer.example.invalid/jwks"),
            ("access_token", "aaaaaaaaaaaaaaaaaaaaaaaa"),
            ("client_secret", "aaaaaaaaaaaaaaaaaaaaaaaa"),
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
                err.is_refusal() || matches!(err, IdentitySecurityError::Schema(_)),
                "{field}"
            );
        }
    }

    #[test]
    fn a_trace_that_is_not_synthetic_or_not_replay_is_refused() {
        let mut value = trace_value();
        value["synthetic"] = json!(false);
        let err = parse_trace(&serde_json::to_vec(&value).expect("serializes"), "trace")
            .expect_err("must be refused");
        assert!(err.is_refusal() || matches!(err, IdentitySecurityError::Schema(_)));

        let mut value = trace_value();
        value["mode"] = json!("SIMULATED");
        let err = parse_trace(&serde_json::to_vec(&value).expect("serializes"), "trace")
            .expect_err("must be refused");
        assert!(err.is_refusal() || matches!(err, IdentitySecurityError::Schema(_)));
    }

    #[test]
    fn a_trace_cannot_raise_the_trial_ceiling() {
        let mut value = trace_value();
        let trial = value["trials"][0].clone();
        value["trials"] = json!(vec![trial; (crate::limits::HARD_MAX_TRIALS + 1) as usize]);
        let err = parse_trace(&serde_json::to_vec(&value).expect("serializes"), "trace")
            .expect_err("must be refused");
        assert!(err.is_refusal() || matches!(err, IdentitySecurityError::Schema(_)));
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
        assert_eq!(loaded.trace.trace_id, "trace-identity-lab-001");
        assert!(loaded.content_digest.starts_with("sha256:"));
        assert_eq!(loaded.source_path, path);
    }
}
