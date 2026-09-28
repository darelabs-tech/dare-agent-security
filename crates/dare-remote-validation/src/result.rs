//! The remote result and the five artifacts (BLUEPRINT §5.2).
//!
//! `RemoteResult` carries no wall-clock value except the observed window,
//! copied from the capture, so a live run and `replay_capture` over its
//! capture produce byte-identical results (O-03).

use std::collections::BTreeSet;

use dare_security_evidence::{SecurityEvidence, Verdict};
use serde::Serialize;
use serde_json::Value;

use crate::audit::AuditRecord;
use crate::canonical::digest;
use crate::capture::Capture;
use crate::engines::EngineOutcome;
use crate::error::{RemoteError, Result};
use crate::evidence::ObservedWindow;
use crate::ledger::OutputLedger;
use crate::outcome::{StopReason, TransportOutcome};
use crate::plan::EngineKind;
use crate::protocol::Protocol;

pub const RESULT_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/remote-validation/v1/result.schema.json";

pub const BOUNDED_CLAIM: &str = "Each verdict is scoped to the listed scenario, sent to this origin, \
within the observed window, under the recorded authorization. A PASS is not a claim that the target \
is secure: it covers only the tested vector and relies on any target-reported fields listed with it.";

#[derive(Debug, Clone, Serialize)]
pub struct RunResult {
    pub engine: EngineKind,
    pub scenario_id: String,
    pub scenario_digest: String,
    pub engine_verdict: Verdict,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unfinished: Option<StopReason>,
    pub self_reported_fields: BTreeSet<&'static str>,
    pub not_observable: Vec<&'static str>,
    pub exchanges: u32,
    pub engine_result: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemoteResult {
    pub schema_version: &'static str,
    pub schema_id: &'static str,
    pub authorization_id: String,
    pub authorization_digest: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub origin: String,
    pub protocol: Protocol,
    pub capture_id: String,
    pub capture_digest: String,
    pub audit_digest: String,
    pub observed_window: ObservedWindow,
    pub stop_reason: StopReason,
    pub requests: u32,
    pub verdict: Verdict,
    pub runs: Vec<RunResult>,
    pub bounded_claim: &'static str,
}

/// FAIL stands; then ERROR; then INCONCLUSIVE; PASS only when every run
/// passed. No runs is INCONCLUSIVE.
pub fn aggregate(verdicts: impl IntoIterator<Item = Verdict>) -> Verdict {
    let all: Vec<Verdict> = verdicts.into_iter().collect();
    if all.is_empty() {
        Verdict::Inconclusive
    } else if all.contains(&Verdict::Fail) {
        Verdict::Fail
    } else if all.contains(&Verdict::Error) {
        Verdict::Error
    } else if all.contains(&Verdict::Inconclusive) {
        Verdict::Inconclusive
    } else {
        Verdict::Pass
    }
}

pub struct Header<'a> {
    pub authorization_id: &'a str,
    pub authorization_digest: &'a str,
    pub plan_id: &'a str,
    pub plan_digest: &'a str,
    pub protocol: Protocol,
}

impl RemoteResult {
    pub fn build(
        header: Header<'_>,
        capture: &Capture,
        audit: &AuditRecord,
        outcomes: &[(String, EngineOutcome)],
    ) -> Result<RemoteResult> {
        let runs: Vec<RunResult> = outcomes
            .iter()
            .map(|(scenario_digest, o)| RunResult {
                engine: o.engine,
                scenario_id: o.scenario_id.clone(),
                scenario_digest: scenario_digest.clone(),
                engine_verdict: o.engine_verdict,
                verdict: o.verdict,
                transport: o.transport,
                unfinished: o.unfinished,
                self_reported_fields: o.self_reported_fields.clone(),
                not_observable: o.not_observable.clone(),
                exchanges: u32::try_from(
                    crate::engines::entries_for(capture, o.engine, &o.scenario_id).count(),
                )
                .unwrap_or(u32::MAX),
                engine_result: o.result.clone(),
            })
            .collect();
        Ok(RemoteResult {
            schema_version: "1",
            schema_id: RESULT_SCHEMA_ID,
            authorization_id: header.authorization_id.to_owned(),
            authorization_digest: header.authorization_digest.to_owned(),
            plan_id: header.plan_id.to_owned(),
            plan_digest: header.plan_digest.to_owned(),
            origin: capture.origin.clone(),
            protocol: header.protocol,
            capture_id: capture.capture_id.clone(),
            capture_digest: digest(capture)?,
            audit_digest: digest(audit)?,
            observed_window: ObservedWindow {
                from: capture.started_at.clone(),
                to: capture.ended_at.clone(),
            },
            stop_reason: capture.stop_reason,
            requests: u32::try_from(capture.entries.len()).unwrap_or(u32::MAX),
            verdict: aggregate(runs.iter().map(|r| r.verdict)),
            runs,
            bounded_claim: BOUNDED_CLAIM,
        })
    }
}

fn verdict_word(v: Verdict) -> &'static str {
    match v {
        Verdict::Pass => "PASS",
        Verdict::Fail => "FAIL",
        Verdict::Inconclusive => "INCONCLUSIVE",
        Verdict::Error => "ERROR",
    }
}

/// `summary.md`. Every PASS that relies on a target-reported field says so
/// (Review BQ-2), and every run lists what cannot be observed remotely.
pub fn render_summary(result: &RemoteResult) -> String {
    let mut out = String::new();
    out.push_str("# Remote validation\n\n");
    out.push_str(&format!(
        "- Verdict: **{}**\n",
        verdict_word(result.verdict)
    ));
    out.push_str(&format!("- Origin: `{}`\n", result.origin));
    out.push_str(&format!(
        "- Authorization: `{}` ({})\n",
        result.authorization_id, result.authorization_digest
    ));
    out.push_str(&format!(
        "- Plan: `{}` ({})\n",
        result.plan_id, result.plan_digest
    ));
    out.push_str(&format!(
        "- Observed window: {} to {}\n",
        result.observed_window.from, result.observed_window.to
    ));
    out.push_str(&format!(
        "- Requests: {}; stop reason: {}\n",
        result.requests,
        result.stop_reason.as_str()
    ));
    out.push_str(&format!(
        "- Capture: `{}` ({})\n\n",
        result.capture_id, result.capture_digest
    ));
    out.push_str(
        "| Engine | Scenario | Verdict | Transport | Unfinished |\n|---|---|---|---|---|\n",
    );
    for run in &result.runs {
        out.push_str(&format!(
            "| {} | `{}` | {} | {} | {} |\n",
            run.engine.as_str(),
            run.scenario_id,
            verdict_word(run.verdict),
            run.transport.map_or("—", TransportOutcome::as_str),
            run.unfinished.map_or("—", StopReason::as_str),
        ));
    }
    out.push('\n');
    for run in &result.runs {
        if run.verdict == Verdict::Pass {
            for field in &run.self_reported_fields {
                out.push_str(&format!(
                    "- `{}`: PASS relies on target-reported `{field}`\n",
                    run.scenario_id
                ));
            }
        }
        if !run.not_observable.is_empty() {
            out.push_str(&format!(
                "- `{}`: not observable remotely: {}\n",
                run.scenario_id,
                run.not_observable.join(", ")
            ));
        }
    }
    out.push_str(&format!("\n{}\n", result.bounded_claim));
    out
}

pub const RESULT_FILE: &str = "remote-result.json";
pub const CAPTURE_FILE: &str = "remote-capture.json";
pub const EVIDENCE_FILE: &str = "remote-evidence.json";
pub const AUDIT_FILE: &str = "remote-audit.json";
pub const SUMMARY_FILE: &str = "summary.md";

/// One artifact, scrubbed and charged.
pub struct Artifact {
    pub name: &'static str,
    pub bytes: Vec<u8>,
}

fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|_| RemoteError::Serialization("artifact"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// The five artifacts, each admitted through the ledger.
pub fn render_artifacts(
    ledger: &mut OutputLedger,
    result: &RemoteResult,
    capture: &Capture,
    evidence: &[SecurityEvidence],
    audit: &AuditRecord,
) -> Result<Vec<Artifact>> {
    Ok(vec![
        Artifact {
            name: RESULT_FILE,
            bytes: ledger.admit(&json(result)?)?,
        },
        Artifact {
            name: CAPTURE_FILE,
            bytes: ledger.admit(&json(capture)?)?,
        },
        Artifact {
            name: EVIDENCE_FILE,
            bytes: ledger.admit(&json(&evidence)?)?,
        },
        Artifact {
            name: AUDIT_FILE,
            bytes: ledger.admit(&json(audit)?)?,
        },
        Artifact {
            name: SUMMARY_FILE,
            bytes: ledger.admit(render_summary(result).as_bytes())?,
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_stands_over_everything_and_pass_needs_every_run() {
        use Verdict::*;
        assert_eq!(aggregate([Pass, Error, Fail]), Fail);
        assert_eq!(aggregate([Pass, Error, Inconclusive]), Error);
        assert_eq!(aggregate([Pass, Inconclusive]), Inconclusive);
        assert_eq!(aggregate([Pass, Pass]), Pass);
        assert_eq!(aggregate([]), Inconclusive);
    }
}
