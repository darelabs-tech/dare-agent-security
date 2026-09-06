//! The simulated adapter.
//!
//! Stages observations deterministically from approved scenario data. It can
//! vary exactly one thing — the routing metadata a request carried — because
//! that is the one authorization-relevant field a *reference implementation*
//! legitimately gets wrong, and binding it would make the header/body
//! invariants untestable.
//!
//! Everything else comes from the scenario. The adapter cannot invent a
//! resource, an issuer, a token or a scope, so no staged behaviour can widen
//! what was approved.

use crate::error::{McpAuthSecurityError, Result};
use crate::harness::{HarnessAdapter, HarnessMode, RawHarnessError, RawTrialOutput, TrialRequest};
use crate::model::{McpAuthScenario, ReferenceBehavior};
use crate::source::HarnessErrorKind;

/// Build the raw output for one behaviour.
pub fn stage(scenario: &McpAuthScenario, behavior: ReferenceBehavior) -> Result<RawTrialOutput> {
    use ReferenceBehavior as B;

    if behavior == B::HarnessFailure {
        return Ok(RawTrialOutput {
            harness_error: Some(RawHarnessError {
                kind: HarnessErrorKind::AdapterFailure,
                detail: "the staged reference harness failed before observing anything".to_owned(),
            }),
            ..RawTrialOutput::default()
        });
    }

    if behavior == B::NoRelevantObservation {
        // Deliberately empty. The channels a contract needs are absent, so the
        // evaluator must say INCONCLUSIVE rather than PASS.
        return Ok(RawTrialOutput::default());
    }

    let mut output = RawTrialOutput {
        observed_requests: scenario.requests.clone(),
        harness_error: None,
    };

    // Only routing metadata is staged. Every other behaviour is expressed by
    // the scenario's own declared evidence, which the adapter passes through
    // untouched — that is what stops a staged "attack" from widening authority.
    match behavior {
        B::MethodHeaderBodyMismatch => {
            let request = output.observed_requests.first_mut().ok_or_else(|| {
                McpAuthSecurityError::invalid(format!(
                    "scenario `{}` declares no request, so a method mismatch cannot be staged",
                    scenario.id
                ))
            })?;
            let body = request.operation.method.clone();
            let other = if body == "tools/call" {
                "resources/read"
            } else {
                "tools/call"
            };
            request.headers.method = Some(other.to_owned());
        }
        B::NameHeaderBodyMismatch => {
            let request = output.observed_requests.first_mut().ok_or_else(|| {
                McpAuthSecurityError::invalid(format!(
                    "scenario `{}` declares no request, so a name mismatch cannot be staged",
                    scenario.id
                ))
            })?;
            let body = request.operation.name.clone().unwrap_or_default();
            request.headers.name = Some(format!("{body}-other"));
        }
        _ => {}
    }

    Ok(output)
}

/// Deterministic staging from approved scenario data only.
#[derive(Debug, Default, Clone, Copy)]
pub struct SimulatedAdapter;

impl SimulatedAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl HarnessAdapter for SimulatedAdapter {
    fn mode(&self) -> HarnessMode {
        HarnessMode::Simulated
    }

    fn observe(&self, request: &TrialRequest<'_>) -> Result<RawTrialOutput> {
        let behavior = request
            .scenario
            .lab
            .as_ref()
            .map(|lab| lab.reference_behavior)
            .ok_or_else(|| {
                McpAuthSecurityError::invalid(format!(
                    "scenario `{}` declares no lab reference behavior, so there is nothing to \
                     stage",
                    request.scenario.id
                ))
            })?;
        stage(request.scenario, behavior)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::tests::scenario;
    use crate::invariant::evaluate;
    use crate::model::McpAuthInvariantType;
    use crate::Verdict;

    fn observed(behavior: ReferenceBehavior) -> Vec<crate::observation::McpAuthObservation> {
        let mut base = scenario();
        base.lab = Some(crate::model::McpAuthLabSpec {
            reference_behavior: behavior,
        });
        let raw = stage(&base, behavior).expect("stages");
        crate::harness::normalize(&raw, &base)
    }

    #[test]
    fn a_compliant_run_stages_the_approved_requests_unchanged() {
        let raw = stage(&scenario(), ReferenceBehavior::Compliant).expect("stages");
        assert_eq!(raw.observed_requests, scenario().requests);
        assert!(raw.harness_error.is_none());
    }

    #[test]
    fn a_method_mismatch_is_staged_on_the_header_only() {
        // The body stays exactly as approved. Only the routed metadata moves,
        // which is what makes the mismatch a mismatch rather than a rewrite.
        let raw = stage(&scenario(), ReferenceBehavior::MethodHeaderBodyMismatch).expect("stages");
        assert_eq!(
            raw.observed_requests[0].operation,
            scenario().requests[0].operation
        );
        assert_ne!(
            raw.observed_requests[0].headers.method,
            scenario().requests[0].headers.method
        );

        let outcome = evaluate(
            McpAuthInvariantType::McpMethodHeaderBodyBindingPreserved,
            &scenario(),
            &observed(ReferenceBehavior::MethodHeaderBodyMismatch),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
    }

    #[test]
    fn a_name_mismatch_is_staged_on_the_header_only() {
        let outcome = evaluate(
            McpAuthInvariantType::McpNameHeaderBodyBindingPreserved,
            &scenario(),
            &observed(ReferenceBehavior::NameHeaderBodyMismatch),
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
    }

    #[test]
    fn a_harness_failure_produces_an_error_rather_than_a_verdict() {
        let raw = stage(&scenario(), ReferenceBehavior::HarnessFailure).expect("stages");
        assert!(raw.harness_error.is_some());
        assert!(raw.observed_requests.is_empty());
    }

    #[test]
    fn the_no_observation_behaviour_stages_nothing_at_all() {
        // The INCONCLUSIVE fixture. An empty run must never reach PASS.
        let raw = stage(&scenario(), ReferenceBehavior::NoRelevantObservation).expect("stages");
        assert!(raw.observed_requests.is_empty());
        assert!(raw.harness_error.is_none());

        let outcome = evaluate(
            McpAuthInvariantType::McpMethodHeaderBodyBindingPreserved,
            &scenario(),
            &crate::harness::normalize(&raw, &{
                let mut s = scenario();
                // Strip the scenario's own evidence too, so nothing else fills
                // the channels this invariant needs.
                s.tokens = Default::default();
                s
            }),
        );
        assert_eq!(outcome.verdict, Verdict::Inconclusive);
    }

    #[test]
    fn the_adapter_reports_its_mode_and_never_a_verdict() {
        let adapter = SimulatedAdapter::new();
        assert_eq!(adapter.mode(), HarnessMode::Simulated);
        assert!(adapter.mode().is_synthetic());
        assert!(adapter.observations_are_synthetic());
    }

    #[test]
    fn a_scenario_with_no_lab_behaviour_is_refused_rather_than_guessed() {
        let mut base = scenario();
        base.lab = None;
        let adapter = SimulatedAdapter::new();
        let err = adapter
            .observe(&TrialRequest {
                trial_index: 0,
                scenario: &base,
            })
            .expect_err("must be refused");
        assert!(err.to_string().contains("nothing to stage"));
    }

    #[test]
    fn staging_is_deterministic() {
        let first = stage(&scenario(), ReferenceBehavior::MethodHeaderBodyMismatch).unwrap();
        let second = stage(&scenario(), ReferenceBehavior::MethodHeaderBodyMismatch).unwrap();
        assert_eq!(first, second);
    }
}
