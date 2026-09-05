//! Additive tool-security product metadata (Cycle 014).
//!
//! Built from existing v1 artifacts in the same style as the Cycle 012 Agentic
//! and Cycle 013 Prompt Injection blocks. No existing summary, findings or
//! coverage schema is modified.
//!
//! The reporting contract this module enforces is that a finite corpus result
//! is never rendered as universal tool security. Tool poisoning and tool misuse
//! are reported as separate dimensions, each surface is reported as tested, not
//! tested or not applicable, and the counts are always present so a reader can
//! see how much was actually exercised.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Whether a surface was exercised in this assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SurfaceState {
    /// At least one scenario exercised this surface.
    Tested,
    /// The target has this surface but nothing exercised it.
    NotTested,
    /// The target has no such surface.
    NotApplicable,
}

impl SurfaceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tested => "TESTED",
            Self::NotTested => "NOT_TESTED",
            Self::NotApplicable => "NOT_APPLICABLE",
        }
    }
}

/// The poisoning surface areas, reported separately.
pub const POISONING_SURFACES: [&str; 5] = [
    "DESCRIPTION",
    "INPUT_SCHEMA",
    "ANNOTATIONS",
    "METADATA",
    "OUTPUT",
];

/// The misuse surfaces, reported separately.
pub const MISUSE_SURFACES: [&str; 5] = [
    "SELECTION",
    "ARGUMENTS",
    "CHAIN",
    "INVOCATION",
    "OUTPUT_ESCALATION",
];

/// Counts an operator needs in order to judge how much was actually validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSecurityCounts {
    pub scenarios: u32,
    pub trials: u32,
    /// Structured tool requests observed. Observed, never dispatched.
    pub tool_requests: u32,
    /// Deepest tool-chain depth observed across the assessment.
    pub max_chain_depth: u32,
    pub violations: u32,
    pub inconclusive: u32,
    pub errors: u32,
}

/// One scenario's contribution to the product view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSecurityScenarioSummary {
    pub scenario_id: String,
    pub property_id: String,
    /// `POISONING` or `MISUSE`. Never merged.
    pub class: String,
    pub family: String,
    pub invariant: String,
    pub mode: String,
    pub synthetic: bool,
    pub verdict: String,
    pub trials_planned: u32,
    pub trials_executed: u32,
    pub tool_requests: u32,
    pub violations: u32,
}

/// Additive metadata block attached to the product view model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSecurityMetadata {
    pub schema_id: String,
    pub schema_version: String,
    pub profile: String,
    /// Tool poisoning, as its own dimension.
    pub tool_poisoning: SurfaceState,
    /// Tool misuse, as its own dimension. Never merged with poisoning.
    pub tool_misuse: SurfaceState,
    /// Per-area poisoning coverage, keyed by surface area.
    pub poisoning_surfaces: BTreeMap<String, SurfaceState>,
    /// Per-surface misuse coverage.
    pub misuse_surfaces: BTreeMap<String, SurfaceState>,
    pub counts: ToolSecurityCounts,
    pub scenarios: Vec<ToolSecurityScenarioSummary>,
    /// Bounded-claim statement. Never a universal security assertion.
    pub assurance_note: String,
    pub limitations: Vec<String>,
}

pub const TOOL_SECURITY_METADATA_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/product/additive/tool-security-metadata-2026";

/// Wording used whenever no violation was observed.
///
/// This is the approved phrasing, verbatim. It describes what was tested rather
/// than what is secure.
pub const BOUNDED_PASS_NOTE: &str =
    "No tool-security invariant violation was observed for the tested vectors under the recorded \
     conditions. This is a finite-corpus result and is not a claim that the tool surface resists \
     poisoning or misuse in general.";

pub const BOUNDED_VIOLATION_NOTE: &str =
    "At least one deterministic tool-security invariant was violated under the recorded \
     conditions. Absence of further violations does not imply the remaining vectors are safe.";

pub const BOUNDED_INCONCLUSIVE_NOTE: &str =
    "Evidence was insufficient to decide at least one tool-security invariant. An inconclusive \
     result is not a pass and must not be reported as one.";

/// Phrases that would overstate what a finite corpus can establish.
const FORBIDDEN_CLAIMS: [&str; 10] = [
    "tool secure",
    "tools are secure",
    "tool security guaranteed",
    "safe tools",
    "immune",
    "fully protected",
    "guaranteed secure",
    "cannot be poisoned",
    "cannot be misused",
    "no longer vulnerable",
];

/// Refuse any rendered text that overstates the result.
pub fn assert_bounded_claim(text: &str) -> Result<()> {
    let lowered = text.to_lowercase();
    for forbidden in FORBIDDEN_CLAIMS {
        if lowered.contains(forbidden) {
            return Err(crate::error::ProductError::internal(format!(
                "refusing to render an unbounded tool-security claim: {forbidden}"
            )));
        }
    }
    Ok(())
}

/// Inputs one scenario result contributes.
///
/// Kept protocol-neutral so the product layer does not depend on the engine
/// crate's concrete types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolScenarioOutcome {
    pub scenario_id: String,
    pub property_id: String,
    /// `POISONING` or `MISUSE`.
    pub class: String,
    pub family: String,
    /// The surface area or misuse surface this family exercises.
    pub surface: String,
    pub invariant: String,
    pub mode: String,
    pub synthetic: bool,
    /// `PASS`, `FAIL`, `INCONCLUSIVE` or `ERROR`.
    pub verdict: String,
    pub trials_planned: u32,
    pub trials_executed: u32,
    pub tool_requests: u32,
    pub max_chain_depth: u32,
    pub violations: u32,
}

/// Which surfaces the target actually has.
///
/// Kept explicit so "not applicable" is a stated fact about the target rather
/// than an inference from an empty result set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolSurfaceAvailability {
    pub poisoning_available: bool,
    pub misuse_available: bool,
}

impl Default for ToolSurfaceAvailability {
    fn default() -> Self {
        Self {
            poisoning_available: true,
            misuse_available: true,
        }
    }
}

fn state_for(exercised: bool, available: bool) -> SurfaceState {
    if exercised {
        SurfaceState::Tested
    } else if available {
        SurfaceState::NotTested
    } else {
        SurfaceState::NotApplicable
    }
}

/// Build the additive metadata block.
pub fn build_tool_security_metadata(
    profile: &str,
    outcomes: &[ToolScenarioOutcome],
    availability: ToolSurfaceAvailability,
) -> Result<ToolSecurityMetadata> {
    let mut counts = ToolSecurityCounts {
        scenarios: outcomes.len() as u32,
        ..ToolSecurityCounts::default()
    };
    for outcome in outcomes {
        counts.trials += outcome.trials_executed;
        counts.tool_requests += outcome.tool_requests;
        counts.max_chain_depth = counts.max_chain_depth.max(outcome.max_chain_depth);
        counts.violations += outcome.violations;
        match outcome.verdict.as_str() {
            "INCONCLUSIVE" => counts.inconclusive += 1,
            "ERROR" => counts.errors += 1,
            _ => {}
        }
    }

    let exercised = |class: &str, surface: &str| {
        outcomes
            .iter()
            .any(|outcome| outcome.class == class && outcome.surface == surface)
    };
    let class_exercised = |class: &str| outcomes.iter().any(|outcome| outcome.class == class);

    let poisoning_surfaces: BTreeMap<String, SurfaceState> = POISONING_SURFACES
        .iter()
        .map(|surface| {
            (
                (*surface).to_owned(),
                state_for(
                    exercised("POISONING", surface),
                    availability.poisoning_available,
                ),
            )
        })
        .collect();
    let misuse_surfaces: BTreeMap<String, SurfaceState> = MISUSE_SURFACES
        .iter()
        .map(|surface| {
            (
                (*surface).to_owned(),
                state_for(exercised("MISUSE", surface), availability.misuse_available),
            )
        })
        .collect();

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
        "Structured tool requests were observed and never dispatched; no tool was executed."
            .to_owned(),
        "No live MCP server, remote provider or production system was exercised.".to_owned(),
    ];
    if outcomes.iter().any(|outcome| outcome.synthetic) {
        limitations.push(
            "Some observations were synthetic and describe a reference agent, not a production one."
                .to_owned(),
        );
    }
    if !class_exercised("POISONING") {
        limitations.push("Tool poisoning was not exercised in this run.".to_owned());
    }
    if !class_exercised("MISUSE") {
        limitations.push("Tool misuse was not exercised in this run.".to_owned());
    }
    for (surface, state) in poisoning_surfaces.iter().chain(misuse_surfaces.iter()) {
        if *state == SurfaceState::NotTested {
            limitations.push(format!("Surface {surface} was not exercised in this run."));
        }
    }

    let metadata = ToolSecurityMetadata {
        schema_id: TOOL_SECURITY_METADATA_SCHEMA_ID.to_owned(),
        schema_version: "1.0.0".to_owned(),
        profile: profile.to_owned(),
        tool_poisoning: state_for(
            class_exercised("POISONING"),
            availability.poisoning_available,
        ),
        tool_misuse: state_for(class_exercised("MISUSE"), availability.misuse_available),
        poisoning_surfaces,
        misuse_surfaces,
        counts,
        scenarios: outcomes
            .iter()
            .map(|outcome| ToolSecurityScenarioSummary {
                scenario_id: outcome.scenario_id.clone(),
                property_id: outcome.property_id.clone(),
                class: outcome.class.clone(),
                family: outcome.family.clone(),
                invariant: outcome.invariant.clone(),
                mode: outcome.mode.clone(),
                synthetic: outcome.synthetic,
                verdict: outcome.verdict.clone(),
                trials_planned: outcome.trials_planned,
                trials_executed: outcome.trials_executed,
                tool_requests: outcome.tool_requests,
                violations: outcome.violations,
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

    fn outcome(class: &str, surface: &str, verdict: &str) -> ToolScenarioOutcome {
        ToolScenarioOutcome {
            scenario_id: "TOOL-LAB-001".to_owned(),
            property_id: "AGENT.TOOL.METADATA_TRUST_BOUNDARY".to_owned(),
            class: class.to_owned(),
            family: "TOOL_DESCRIPTION_INSTRUCTION_POISONING".to_owned(),
            surface: surface.to_owned(),
            invariant: "TOOL_METADATA_NOT_AUTHORITATIVE".to_owned(),
            mode: "SIMULATED".to_owned(),
            synthetic: true,
            verdict: verdict.to_owned(),
            trials_planned: 3,
            trials_executed: 3,
            tool_requests: 3,
            max_chain_depth: 2,
            violations: if verdict == "FAIL" { 2 } else { 0 },
        }
    }

    fn build(outcomes: &[ToolScenarioOutcome]) -> ToolSecurityMetadata {
        build_tool_security_metadata(
            "tool-security-baseline-2026",
            outcomes,
            ToolSurfaceAvailability::default(),
        )
        .expect("metadata builds")
    }

    #[test]
    fn poisoning_and_misuse_are_reported_as_separate_dimensions() {
        let metadata = build(&[outcome("POISONING", "DESCRIPTION", "PASS")]);
        assert_eq!(metadata.tool_poisoning, SurfaceState::Tested);
        assert_eq!(
            metadata.tool_misuse,
            SurfaceState::NotTested,
            "an untested dimension must never read as passing"
        );

        let metadata = build(&[outcome("MISUSE", "SELECTION", "PASS")]);
        assert_eq!(metadata.tool_poisoning, SurfaceState::NotTested);
        assert_eq!(metadata.tool_misuse, SurfaceState::Tested);
    }

    #[test]
    fn every_surface_is_reported_individually() {
        let metadata = build(&[
            outcome("POISONING", "DESCRIPTION", "PASS"),
            outcome("MISUSE", "CHAIN", "PASS"),
        ]);
        assert_eq!(metadata.poisoning_surfaces.len(), 5);
        assert_eq!(metadata.misuse_surfaces.len(), 5);
        assert_eq!(
            metadata.poisoning_surfaces["DESCRIPTION"],
            SurfaceState::Tested
        );
        assert_eq!(
            metadata.poisoning_surfaces["OUTPUT"],
            SurfaceState::NotTested
        );
        assert_eq!(metadata.misuse_surfaces["CHAIN"], SurfaceState::Tested);
        assert_eq!(
            metadata.misuse_surfaces["INVOCATION"],
            SurfaceState::NotTested
        );
    }

    #[test]
    fn a_surface_the_target_lacks_is_not_applicable_rather_than_untested() {
        let metadata = build_tool_security_metadata(
            "tool-security-baseline-2026",
            &[outcome("POISONING", "DESCRIPTION", "PASS")],
            ToolSurfaceAvailability {
                poisoning_available: true,
                misuse_available: false,
            },
        )
        .expect("metadata builds");
        assert_eq!(metadata.tool_misuse, SurfaceState::NotApplicable);
        for state in metadata.misuse_surfaces.values() {
            assert_eq!(*state, SurfaceState::NotApplicable);
        }
        // And "not applicable" is not silently listed as a gap to close.
        assert!(!metadata
            .limitations
            .iter()
            .any(|limit| limit.contains("Surface SELECTION")));
    }

    #[test]
    fn the_counts_the_approval_requires_are_all_present() {
        let metadata = build(&[
            outcome("POISONING", "DESCRIPTION", "FAIL"),
            outcome("MISUSE", "CHAIN", "INCONCLUSIVE"),
        ]);
        assert_eq!(metadata.counts.scenarios, 2);
        assert_eq!(metadata.counts.trials, 6);
        assert_eq!(metadata.counts.tool_requests, 6);
        assert_eq!(metadata.counts.max_chain_depth, 2);
        assert_eq!(metadata.counts.violations, 2);
        assert_eq!(metadata.counts.inconclusive, 1);
        assert_eq!(metadata.counts.errors, 0);
    }

    #[test]
    fn the_pass_note_is_the_approved_bounded_wording() {
        let metadata = build(&[outcome("POISONING", "DESCRIPTION", "PASS")]);
        assert!(metadata.assurance_note.starts_with(
            "No tool-security invariant violation was observed for the tested vectors under the \
             recorded conditions."
        ));
    }

    #[test]
    fn an_inconclusive_result_is_never_reported_as_a_pass() {
        let metadata = build(&[outcome("MISUSE", "SELECTION", "INCONCLUSIVE")]);
        assert_eq!(metadata.assurance_note, BOUNDED_INCONCLUSIVE_NOTE);
        assert!(metadata.assurance_note.contains("is not a pass"));

        let metadata = build(&[outcome("MISUSE", "SELECTION", "ERROR")]);
        assert_eq!(metadata.assurance_note, BOUNDED_INCONCLUSIVE_NOTE);
    }

    #[test]
    fn a_violation_note_does_not_imply_the_rest_is_safe() {
        let metadata = build(&[outcome("POISONING", "DESCRIPTION", "FAIL")]);
        assert_eq!(metadata.assurance_note, BOUNDED_VIOLATION_NOTE);
        assert!(metadata
            .assurance_note
            .contains("does not imply the remaining vectors are safe"));
    }

    #[test]
    fn no_rendered_block_can_contain_an_unbounded_claim() {
        for verdict in ["PASS", "FAIL", "INCONCLUSIVE", "ERROR"] {
            let metadata = build(&[outcome("POISONING", "DESCRIPTION", verdict)]);
            let rendered = serde_json::to_string(&metadata).expect("serializes");
            assert_bounded_claim(&rendered).expect("bounded");
        }

        for claim in [
            "the tools are secure",
            "Safe Tools",
            "the agent is immune",
            "fully protected",
            "guaranteed secure",
            "the surface cannot be poisoned",
            "it cannot be misused",
            "no longer vulnerable",
        ] {
            assert!(assert_bounded_claim(claim).is_err(), "must refuse: {claim}");
        }
    }

    #[test]
    fn the_no_dispatch_limitation_is_always_stated() {
        let metadata = build(&[outcome("MISUSE", "ARGUMENTS", "FAIL")]);
        assert!(metadata
            .limitations
            .iter()
            .any(|limit| limit.contains("observed and never dispatched; no tool was executed")));
        assert!(metadata
            .limitations
            .iter()
            .any(|limit| limit.contains("No live MCP server, remote provider")));
    }

    #[test]
    fn synthetic_observations_are_declared_as_such() {
        let metadata = build(&[outcome("POISONING", "DESCRIPTION", "PASS")]);
        assert!(metadata
            .limitations
            .iter()
            .any(|limit| limit.contains("synthetic and describe a reference agent")));

        let mut recorded = outcome("POISONING", "DESCRIPTION", "PASS");
        recorded.synthetic = false;
        recorded.mode = "REPLAY".to_owned();
        let metadata = build(&[recorded]);
        assert!(!metadata
            .limitations
            .iter()
            .any(|limit| limit.contains("synthetic and describe a reference agent")));
    }

    #[test]
    fn an_empty_assessment_claims_nothing() {
        let metadata = build(&[]);
        assert_eq!(metadata.counts.scenarios, 0);
        assert_eq!(metadata.tool_poisoning, SurfaceState::NotTested);
        assert_eq!(metadata.tool_misuse, SurfaceState::NotTested);
        // Nothing was tested, so the note must not be the pass wording.
        assert_eq!(metadata.assurance_note, BOUNDED_PASS_NOTE);
        assert!(metadata
            .limitations
            .iter()
            .any(|limit| limit == "Tool poisoning was not exercised in this run."));
        assert!(metadata
            .limitations
            .iter()
            .any(|limit| limit == "Tool misuse was not exercised in this run."));
    }

    #[test]
    fn the_block_round_trips_and_rejects_unknown_fields() {
        let metadata = build(&[outcome("POISONING", "OUTPUT", "PASS")]);
        let encoded = serde_json::to_string(&metadata).expect("serializes");
        let decoded: ToolSecurityMetadata = serde_json::from_str(&encoded).expect("round trips");
        assert_eq!(decoded, metadata);

        let mut value: serde_json::Value = serde_json::from_str(&encoded).expect("value");
        value["live_tool_config"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ToolSecurityMetadata>(value).is_err());
    }
}
