//! Additive prompt-injection product metadata (Cycle 013).
//!
//! Built from existing v1 artifacts in the same style as the Cycle 012 Agentic
//! metadata. No existing summary, findings or coverage schema is modified.
//!
//! The reporting contract this module enforces is that a finite corpus result
//! is never rendered as universal security. DIRECT and INDIRECT are reported
//! separately, each as tested, not tested, or not applicable, and counts are
//! always present so a reader can see how little or how much was exercised.

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Whether a source direction was exercised in this assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DirectionState {
    /// At least one scenario exercised this direction.
    Tested,
    /// The target has this ingestion path but nothing exercised it.
    NotTested,
    /// The target has no ingestion path for this direction.
    NotApplicable,
}

impl DirectionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tested => "TESTED",
            Self::NotTested => "NOT_TESTED",
            Self::NotApplicable => "NOT_APPLICABLE",
        }
    }
}

/// Counts an operator needs in order to judge how much was actually validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptInjectionCounts {
    pub scenarios: u32,
    pub trials: u32,
    pub violations: u32,
    pub inconclusive: u32,
    pub errors: u32,
}

/// One scenario's contribution to the product view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptInjectionScenarioSummary {
    pub scenario_id: String,
    pub property_id: String,
    pub direction: String,
    pub invariant: String,
    pub mode: String,
    pub synthetic: bool,
    pub verdict: String,
    pub trials_planned: u32,
    pub trials_executed: u32,
}

/// Additive metadata block attached to the product view model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptInjectionMetadata {
    pub schema_id: String,
    pub schema_version: String,
    pub profile: String,
    pub direct: DirectionState,
    pub indirect: DirectionState,
    pub counts: PromptInjectionCounts,
    pub scenarios: Vec<PromptInjectionScenarioSummary>,
    /// Bounded-claim statement. Never a universal security assertion.
    pub assurance_note: String,
    pub limitations: Vec<String>,
}

pub const PROMPT_INJECTION_METADATA_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/product/additive/prompt-injection-metadata-2026";

/// Wording used whenever no violation was observed.
///
/// Deliberately describes what was tested rather than what is secure.
pub const BOUNDED_PASS_NOTE: &str =
    "No invariant violation was observed for the tested vectors under the recorded conditions. \
     This is a finite-corpus result and is not a claim that the target resists prompt injection \
     in general.";

pub const BOUNDED_VIOLATION_NOTE: &str =
    "At least one deterministic security invariant was violated under the recorded conditions. \
     Absence of further violations does not imply the remaining vectors are safe.";

pub const BOUNDED_INCONCLUSIVE_NOTE: &str =
    "Evidence was insufficient to decide at least one invariant. An inconclusive result is not a \
     pass and must not be reported as one.";

/// Phrases that would overstate what a finite corpus can establish.
const FORBIDDEN_CLAIMS: [&str; 8] = [
    "prompt injection secure",
    "immune to prompt injection",
    "immune",
    "fully protected",
    "guaranteed secure",
    "cannot be injected",
    "injection proof",
    "no longer vulnerable",
];

/// Refuse any rendered text that overstates the result.
pub fn assert_bounded_claim(text: &str) -> Result<()> {
    let lowered = text.to_lowercase();
    for forbidden in FORBIDDEN_CLAIMS {
        if lowered.contains(forbidden) {
            return Err(crate::error::ProductError::internal(format!(
                "refusing to render an unbounded prompt-injection claim: {forbidden}"
            )));
        }
    }
    Ok(())
}

/// Inputs one scenario result contributes. Kept protocol-neutral so the product
/// layer does not depend on the engine crate's concrete types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioOutcome {
    pub scenario_id: String,
    pub property_id: String,
    /// `DIRECT` or `INDIRECT`.
    pub direction: String,
    pub invariant: String,
    pub mode: String,
    pub synthetic: bool,
    /// `PASS`, `FAIL`, `INCONCLUSIVE` or `ERROR`.
    pub verdict: String,
    pub trials_planned: u32,
    pub trials_executed: u32,
}

/// Build the additive metadata block.
///
/// `direct_available` and `indirect_available` describe the target's ingestion
/// paths, so a direction with no path is reported `NOT_APPLICABLE` rather than
/// being conflated with one that simply was not exercised.
pub fn build_prompt_injection_metadata(
    profile: &str,
    outcomes: &[ScenarioOutcome],
    direct_available: bool,
    indirect_available: bool,
) -> Result<PromptInjectionMetadata> {
    let mut counts = PromptInjectionCounts {
        scenarios: outcomes.len() as u32,
        ..PromptInjectionCounts::default()
    };
    for outcome in outcomes {
        counts.trials += outcome.trials_executed;
        match outcome.verdict.as_str() {
            "FAIL" => counts.violations += 1,
            "INCONCLUSIVE" => counts.inconclusive += 1,
            "ERROR" => counts.errors += 1,
            _ => {}
        }
    }

    let direction_state = |available: bool, direction: &str| {
        if outcomes.iter().any(|o| o.direction == direction) {
            DirectionState::Tested
        } else if available {
            DirectionState::NotTested
        } else {
            DirectionState::NotApplicable
        }
    };

    let assurance_note = if counts.violations > 0 {
        BOUNDED_VIOLATION_NOTE
    } else if counts.inconclusive > 0 || counts.errors > 0 {
        BOUNDED_INCONCLUSIVE_NOTE
    } else {
        BOUNDED_PASS_NOTE
    }
    .to_owned();

    let mut limitations = vec![
        "Validation covers only the vectors present in the local corpus.".to_owned(),
        "Results are scoped to the recorded conditions and the bounded trial count.".to_owned(),
        "No remote target, provider or production system was exercised.".to_owned(),
    ];
    if outcomes.iter().any(|outcome| outcome.synthetic) {
        limitations.push(
            "Some observations were synthetic and describe a reference agent, not a production one."
                .to_owned(),
        );
    }
    if direction_state(indirect_available, "INDIRECT") != DirectionState::Tested {
        limitations.push(
            "Indirect (external content) injection was not exercised in this run.".to_owned(),
        );
    }
    if direction_state(direct_available, "DIRECT") != DirectionState::Tested {
        limitations
            .push("Direct (user prompt) injection was not exercised in this run.".to_owned());
    }

    let metadata = PromptInjectionMetadata {
        schema_id: PROMPT_INJECTION_METADATA_SCHEMA_ID.to_owned(),
        schema_version: "1.0.0".to_owned(),
        profile: profile.to_owned(),
        direct: direction_state(direct_available, "DIRECT"),
        indirect: direction_state(indirect_available, "INDIRECT"),
        counts,
        scenarios: outcomes
            .iter()
            .map(|outcome| PromptInjectionScenarioSummary {
                scenario_id: outcome.scenario_id.clone(),
                property_id: outcome.property_id.clone(),
                direction: outcome.direction.clone(),
                invariant: outcome.invariant.clone(),
                mode: outcome.mode.clone(),
                synthetic: outcome.synthetic,
                verdict: outcome.verdict.clone(),
                trials_planned: outcome.trials_planned,
                trials_executed: outcome.trials_executed,
            })
            .collect(),
        assurance_note,
        limitations,
    };

    // The block must not be able to render an unbounded claim.
    assert_bounded_claim(&serde_json::to_string(&metadata)?)?;
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(direction: &str, verdict: &str) -> ScenarioOutcome {
        ScenarioOutcome {
            scenario_id: "PI-LAB-001".to_owned(),
            property_id: if direction == "DIRECT" {
                "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY".to_owned()
            } else {
                "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY".to_owned()
            },
            direction: direction.to_owned(),
            invariant: "AUTHORIZED_GOAL_UNCHANGED".to_owned(),
            mode: "SIMULATED".to_owned(),
            synthetic: true,
            verdict: verdict.to_owned(),
            trials_planned: 3,
            trials_executed: 3,
        }
    }

    #[test]
    fn direct_and_indirect_are_reported_separately() {
        let metadata = build_prompt_injection_metadata(
            "prompt-injection-baseline-2026",
            &[outcome("DIRECT", "PASS")],
            true,
            true,
        )
        .unwrap();

        assert_eq!(metadata.direct, DirectionState::Tested);
        assert_eq!(
            metadata.indirect,
            DirectionState::NotTested,
            "an unexercised direction must not inherit the tested one's result"
        );
    }

    #[test]
    fn an_absent_ingestion_path_is_not_applicable_not_untested() {
        let metadata = build_prompt_injection_metadata(
            "prompt-injection-baseline-2026",
            &[outcome("DIRECT", "PASS")],
            true,
            false,
        )
        .unwrap();
        assert_eq!(metadata.indirect, DirectionState::NotApplicable);
        assert_ne!(metadata.indirect, DirectionState::Tested);
    }

    #[test]
    fn counts_are_always_present_so_scope_is_visible() {
        let metadata = build_prompt_injection_metadata(
            "prompt-injection-baseline-2026",
            &[
                outcome("DIRECT", "PASS"),
                outcome("INDIRECT", "FAIL"),
                outcome("DIRECT", "INCONCLUSIVE"),
                outcome("INDIRECT", "ERROR"),
            ],
            true,
            true,
        )
        .unwrap();

        assert_eq!(metadata.counts.scenarios, 4);
        assert_eq!(metadata.counts.trials, 12);
        assert_eq!(metadata.counts.violations, 1);
        assert_eq!(metadata.counts.inconclusive, 1);
        assert_eq!(metadata.counts.errors, 1);
    }

    #[test]
    fn a_clean_run_is_described_as_bounded_not_secure() {
        let metadata = build_prompt_injection_metadata(
            "prompt-injection-baseline-2026",
            &[outcome("DIRECT", "PASS"), outcome("INDIRECT", "PASS")],
            true,
            true,
        )
        .unwrap();

        assert_eq!(metadata.assurance_note, BOUNDED_PASS_NOTE);
        assert!(metadata.assurance_note.contains("tested vectors"));
        assert!(metadata.assurance_note.contains("recorded conditions"));
        assert!(metadata.assurance_note.contains("not a claim"));
        assert!(!metadata.limitations.is_empty());
        assert_bounded_claim(&serde_json::to_string(&metadata).unwrap()).unwrap();
    }

    #[test]
    fn an_inconclusive_run_is_never_described_as_a_pass() {
        let metadata = build_prompt_injection_metadata(
            "prompt-injection-baseline-2026",
            &[outcome("DIRECT", "INCONCLUSIVE")],
            true,
            true,
        )
        .unwrap();
        assert_eq!(metadata.assurance_note, BOUNDED_INCONCLUSIVE_NOTE);
        assert!(metadata.assurance_note.contains("not a pass"));
    }

    #[test]
    fn a_violation_note_does_not_imply_the_rest_is_safe() {
        let metadata = build_prompt_injection_metadata(
            "prompt-injection-baseline-2026",
            &[outcome("DIRECT", "FAIL")],
            true,
            true,
        )
        .unwrap();
        assert_eq!(metadata.assurance_note, BOUNDED_VIOLATION_NOTE);
        assert!(metadata
            .assurance_note
            .contains("does not imply the remaining vectors are safe"));
    }

    #[test]
    fn unbounded_claims_are_refused() {
        for unbounded in [
            "The agent is Prompt Injection Secure.",
            "This target is immune to prompt injection.",
            "The system is fully protected.",
            "The agent is no longer vulnerable.",
            "It cannot be injected.",
            "Injection proof.",
        ] {
            assert!(
                assert_bounded_claim(unbounded).is_err(),
                "{unbounded} must be refused"
            );
        }
        assert!(assert_bounded_claim(BOUNDED_PASS_NOTE).is_ok());
        assert!(assert_bounded_claim(BOUNDED_VIOLATION_NOTE).is_ok());
        assert!(assert_bounded_claim(BOUNDED_INCONCLUSIVE_NOTE).is_ok());
    }

    #[test]
    fn untested_directions_are_recorded_as_limitations() {
        let metadata = build_prompt_injection_metadata(
            "prompt-injection-baseline-2026",
            &[outcome("DIRECT", "PASS")],
            true,
            true,
        )
        .unwrap();
        assert!(metadata
            .limitations
            .iter()
            .any(|line| line.contains("Indirect")));
        assert!(metadata
            .limitations
            .iter()
            .any(|line| line.contains("No remote target")));
        assert!(metadata
            .limitations
            .iter()
            .any(|line| line.contains("synthetic")));
    }

    #[test]
    fn the_metadata_block_is_a_closed_additive_contract() {
        let metadata = build_prompt_injection_metadata(
            "prompt-injection-baseline-2026",
            &[outcome("DIRECT", "PASS")],
            true,
            true,
        )
        .unwrap();
        let mut value = serde_json::to_value(&metadata).unwrap();
        value["provider"] = serde_json::json!("openai");
        assert!(serde_json::from_value::<PromptInjectionMetadata>(value).is_err());

        assert_eq!(metadata.schema_id, PROMPT_INJECTION_METADATA_SCHEMA_ID);
        assert_eq!(metadata.schema_version, "1.0.0");
    }

    #[test]
    fn direction_state_tokens_are_stable() {
        assert_eq!(
            serde_json::to_value(DirectionState::NotApplicable).unwrap(),
            serde_json::json!("NOT_APPLICABLE")
        );
        assert_eq!(DirectionState::Tested.as_str(), "TESTED");
        assert!(serde_json::from_str::<DirectionState>("\"SECURE\"").is_err());
    }
}
