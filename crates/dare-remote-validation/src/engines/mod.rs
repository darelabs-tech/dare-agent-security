//! Engine conversions (BLUEPRINT §6).
//!
//! Each engine has two halves: a live half that drives the engine's own
//! runner through an adapter backed by the gateway (its result is discarded),
//! and a verdict half that turns the capture into the engine's existing
//! offline input and lets the engine decide. The verdict half reads only the
//! capture, so `replay_capture` reproduces it without a socket.

use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use dare_security_evidence::{SecurityEvidence, Verdict};
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::capture::{Capture, CaptureEntry};
use crate::gateway::EgressGateway;
use crate::outcome::{overlay, StopReason, TransportOutcome};
use crate::plan::EngineKind;

pub mod a2a;
pub mod mcp_auth;
pub mod multi_turn;
pub mod prompt_injection;

/// The gateway, shared by the adapters of one run.
pub type SharedGateway = Arc<tokio::sync::Mutex<EgressGateway>>;

/// Run async I/O from a synchronous engine adapter (BLUEPRINT AD-08).
pub(crate) fn block_on<F: Future>(handle: &tokio::runtime::Handle, future: F) -> F::Output {
    tokio::task::block_in_place(|| handle.block_on(future))
}

/// Where built-in scenario files live (the CLI's working directory, or the
/// repository root in tests).
#[derive(Debug, Clone)]
pub struct Sources {
    pub root: PathBuf,
}

/// The principal every remote request names when a scenario has none.
pub const DEFAULT_PRINCIPAL: &str = "dare-remote-operator";

/// What one planned run concluded.
#[derive(Debug, Clone, Serialize)]
pub struct EngineOutcome {
    pub engine: EngineKind,
    pub scenario_id: String,
    /// The engine's own verdict over the replayed capture.
    pub engine_verdict: Verdict,
    /// After the transport overlay and the unfinished-run rule.
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unfinished: Option<StopReason>,
    /// Target-reported fields the verdict relied on (Review BQ-2).
    pub self_reported_fields: BTreeSet<&'static str>,
    /// Facts an engine needs that cannot be observed from outside the target.
    pub not_observable: Vec<&'static str>,
    /// The engine's own result document.
    pub result: serde_json::Value,
    #[serde(skip)]
    pub evidence: Vec<SecurityEvidence>,
}

/// The capture entries of one scenario, in order.
pub fn entries_for<'a>(
    capture: &'a Capture,
    engine: EngineKind,
    scenario_id: &'a str,
) -> impl Iterator<Item = &'a CaptureEntry> + 'a {
    capture.entries.iter().filter(move |e| {
        e.scenario_ref.engine == engine && e.scenario_ref.scenario_id == scenario_id
    })
}

/// The first transport outcome among a scenario's entries.
pub fn first_transport(
    capture: &Capture,
    engine: EngineKind,
    scenario_id: &str,
) -> Option<TransportOutcome> {
    entries_for(capture, engine, scenario_id).find_map(|e| e.transport_error)
}

/// Whether the run stopped before this scenario could finish, derived from
/// the capture alone. After any stop other than a first failure, the
/// scenario that was running and every later one are unfinished. After a
/// first failure, the failing scenario finished; every later one is
/// unfinished (never sent).
pub fn unfinished(
    capture: &Capture,
    position: usize,
    planned: &[(EngineKind, String)],
) -> Option<StopReason> {
    if capture.stop_reason == StopReason::Completed {
        return None;
    }
    let running = capture
        .entries
        .last()
        .and_then(|last| {
            planned.iter().position(|(e, s)| {
                *e == last.scenario_ref.engine && *s == last.scenario_ref.scenario_id
            })
        })
        .unwrap_or(0);
    let cut = if capture.stop_reason == StopReason::FirstFail {
        position > running
    } else {
        position >= running
    };
    cut.then_some(capture.stop_reason)
}

/// Combine the engine verdict with the transport overlay and the
/// unfinished-run rule. A FAIL always stands.
pub fn final_verdict(
    engine: Verdict,
    transport: Option<TransportOutcome>,
    unfinished: Option<StopReason>,
) -> Verdict {
    if engine == Verdict::Fail {
        return Verdict::Fail;
    }
    if unfinished.is_some() {
        return Verdict::Inconclusive;
    }
    overlay(engine, transport)
}

/// A deterministic evidence timestamp: the capture's end.
pub fn evidence_time(capture: &Capture) -> OffsetDateTime {
    OffsetDateTime::parse(&capture.ended_at, &Rfc3339).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::tests::capture;

    #[test]
    fn a_fail_stands_and_nothing_else_passes_when_unfinished() {
        for transport in [None, Some(TransportOutcome::Tls)] {
            assert_eq!(
                final_verdict(Verdict::Fail, transport, Some(StopReason::KillSwitch)),
                Verdict::Fail
            );
        }
        assert_eq!(
            final_verdict(Verdict::Pass, None, Some(StopReason::BudgetExhausted)),
            Verdict::Inconclusive
        );
        assert_eq!(final_verdict(Verdict::Pass, None, None), Verdict::Pass);
        assert_eq!(
            final_verdict(Verdict::Pass, Some(TransportOutcome::RateLimited), None),
            Verdict::Inconclusive
        );
    }

    #[test]
    fn unfinished_is_derived_from_the_capture_alone() {
        let planned = vec![
            (EngineKind::PromptInjection, "PI-LAB-001".to_owned()),
            (EngineKind::MultiTurn, "multiturn-lab-001".to_owned()),
            (EngineKind::MultiTurn, "multiturn-lab-002".to_owned()),
        ];
        let mut c = capture(2); // entries belong to multiturn-lab-001
        assert_eq!(unfinished(&c, 0, &planned), None, "completed");
        c.stop_reason = StopReason::KillSwitch;
        assert_eq!(
            unfinished(&c, 0, &planned),
            None,
            "an earlier scenario finished"
        );
        assert_eq!(
            unfinished(&c, 1, &planned),
            Some(StopReason::KillSwitch),
            "the running one"
        );
        assert_eq!(
            unfinished(&c, 2, &planned),
            Some(StopReason::KillSwitch),
            "a later one"
        );
        c.stop_reason = StopReason::FirstFail;
        assert_eq!(
            unfinished(&c, 1, &planned),
            None,
            "the failing scenario finished"
        );
        assert_eq!(
            unfinished(&c, 2, &planned),
            Some(StopReason::FirstFail),
            "a later one never ran"
        );
    }
}
