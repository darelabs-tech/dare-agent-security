//! Additive memory-security product metadata (Cycle 016).
//!
//! Built from existing v1 artifacts in the same style as the Cycle 012 Agentic,
//! Cycle 013 Prompt Injection, Cycle 014 Tool Security and Cycle 015 Identity
//! Security blocks. No existing summary, findings or coverage schema is
//! modified.
//!
//! The reporting contract this module enforces is that a finite corpus result
//! is never rendered as universal memory security. The five surfaces —
//! provenance, trust boundary, tenant/principal, lifecycle and decision
//! influence — are reported separately and never merged, each is reported as
//! tested, not tested, not applicable or inconclusive, and the counts are
//! always present so a reader can see how much was actually exercised.
//!
//! Two further rules are enforced rather than documented: an inconclusive
//! result is never rendered as a pass, and the central relation this cycle
//! rests on — that stored data is not a trusted instruction — is carried in
//! every block, so a report read on its own still says what a memory verdict
//! means.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Whether a surface was exercised in this assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemorySurfaceState {
    /// At least one scenario exercised this surface.
    Tested,
    /// The target has this surface but nothing exercised it.
    NotTested,
    /// The target has no such surface.
    NotApplicable,
    /// A scenario exercised it and the evidence did not decide.
    ///
    /// Distinct from `NOT_TESTED` on purpose: something was looked at and the
    /// answer is unknown, which is not the same as never having looked.
    Inconclusive,
}

impl MemorySurfaceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tested => "TESTED",
            Self::NotTested => "NOT_TESTED",
            Self::NotApplicable => "NOT_APPLICABLE",
            Self::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// The five memory-security surfaces, reported separately.
pub const MEMORY_SURFACES: [&str; 5] = [
    "PROVENANCE",
    "TRUST_BOUNDARY",
    "TENANT_PRINCIPAL",
    "LIFECYCLE",
    "DECISION_INFLUENCE",
];

/// Counts an operator needs in order to judge how much was actually validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySecurityCounts {
    pub scenarios: u32,
    pub trials: u32,
    /// Memory items returned by recalls. Read from fixtures, never persisted.
    pub recall_items: u32,
    pub violations: u32,
    pub inconclusive: u32,
    pub errors: u32,
    /// Always zero. Cycle 016 changes no state and writes to no store.
    pub state_changes: u32,
    /// Always zero. Cycle 016 sends nothing anywhere.
    pub external_egress_bytes: u64,
}

/// One scenario's contribution to the product view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySecurityScenarioSummary {
    pub scenario_id: String,
    pub property_id: String,
    /// One of the five surfaces. Never merged.
    pub surface: String,
    pub invariant: String,
    pub mode: String,
    pub synthetic: bool,
    pub verdict: String,
    pub trials_planned: u32,
    pub trials_executed: u32,
    pub recall_items: u32,
    pub violations: u32,
}

/// Additive metadata block attached to the product view model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySecurityMetadata {
    pub schema_id: String,
    pub schema_version: String,
    pub profile: String,
    /// Per-surface coverage. Each surface stands alone.
    pub surfaces: BTreeMap<String, MemorySurfaceState>,
    pub counts: MemorySecurityCounts,
    pub scenarios: Vec<MemorySecurityScenarioSummary>,
    /// The relation every verdict is measured against.
    pub memory_trust_relation: String,
    /// The rule the availability fixtures exist to state.
    pub availability_rule: String,
    /// Bounded-claim statement. Never a universal security assertion.
    pub assurance_note: String,
    pub limitations: Vec<String>,
    /// Upstream attributions with their own statuses, never conformance claims.
    pub standards_note: String,
    /// What this block deliberately does not cover.
    pub scope_boundary_note: String,
}

pub const MEMORY_SECURITY_METADATA_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/product/additive/memory-security-metadata-2026";

/// Wording used whenever no violation was observed.
///
/// This is the approved phrasing, verbatim. It describes what was tested rather
/// than what is secure.
pub const BOUNDED_PASS_NOTE: &str =
    "No memory-security invariant violation was observed for the tested vectors under the \
     recorded conditions. This is a finite-corpus result and is not a claim that memory, \
     context or recall handling holds in general.";

pub const BOUNDED_VIOLATION_NOTE: &str =
    "At least one deterministic memory-security invariant was violated under the recorded \
     conditions. Absence of further violations does not imply the remaining vectors are safe.";

pub const BOUNDED_INCONCLUSIVE_NOTE: &str =
    "Evidence was insufficient to decide at least one memory-security invariant. An \
     inconclusive result is not a pass and must not be reported as one.";

/// The relation the whole cycle rests on.
pub const MEMORY_TRUST_RELATION: &str =
    "stored_data != trusted_instruction; persisting data records it and confers nothing. Trust \
     is assigned by policy and is never acquired by being written or recalled.";

/// The corollary the recall fixtures exist to state.
pub const AVAILABILITY_RULE: &str =
    "Memory being available to a recall is capability availability and not authorization for it \
     to influence a protected decision.";

/// How upstream sources are attributed.
pub const STANDARDS_NOTE: &str =
    "ASI06 is used as risk taxonomy and context. Using a similar vocabulary is not conformance, \
     and nothing here is a certification against any specification.";

/// What this cycle deliberately leaves to a later one.
///
/// Stated in the artifact rather than only in the docs, because a reader
/// holding one report has no other way to learn that retrieval was never
/// examined and might otherwise read "memory" as covering it.
pub const SCOPE_BOUNDARY_NOTE: &str =
    "This block covers persisted memory and context state only. Retrieval-augmented generation, \
     embedding similarity, vector-store authorization, document-level isolation and \
     cross-document retrieval are not evaluated here and are not implied by any result in it.";

/// Phrases that would overstate what a finite corpus can establish.
const FORBIDDEN_CLAIMS: [&str; 12] = [
    "memory secure",
    "memory is secure",
    "poisoning impossible",
    "no memory poisoning",
    "fully protected",
    "immune",
    "guaranteed secure",
    "cannot be poisoned",
    "cannot be tampered",
    "no longer vulnerable",
    "asi06 compliant",
    "asi06 certified",
];

/// Refuse any rendered text that overstates the result.
pub fn assert_bounded_claim(text: &str) -> Result<()> {
    let lowered = text.to_lowercase();
    for forbidden in FORBIDDEN_CLAIMS {
        if lowered.contains(forbidden) {
            return Err(crate::error::ProductError::internal(format!(
                "refusing to render an unbounded memory-security claim: {forbidden}"
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
pub struct MemoryScenarioOutcome {
    pub scenario_id: String,
    pub property_id: String,
    /// One of `MEMORY_SURFACES`.
    pub surface: String,
    pub invariant: String,
    pub mode: String,
    pub synthetic: bool,
    /// `PASS`, `FAIL`, `INCONCLUSIVE` or `ERROR`.
    pub verdict: String,
    pub trials_planned: u32,
    pub trials_executed: u32,
    pub recall_items: u32,
    pub violations: u32,
}

/// Which surfaces the target actually has.
///
/// Kept explicit so "not applicable" is a stated fact about the target rather
/// than an inference from an empty result set. An agent with no namespaces
/// genuinely has no namespace boundary; one that has them and was never tested
/// is a gap, and the two must not render identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemorySurfaceAvailability {
    pub provenance_available: bool,
    pub trust_boundary_available: bool,
    pub tenant_principal_available: bool,
    pub lifecycle_available: bool,
    pub decision_influence_available: bool,
}

impl Default for MemorySurfaceAvailability {
    fn default() -> Self {
        Self {
            provenance_available: true,
            trust_boundary_available: true,
            tenant_principal_available: true,
            lifecycle_available: true,
            decision_influence_available: true,
        }
    }
}

impl MemorySurfaceAvailability {
    fn available(&self, surface: &str) -> bool {
        match surface {
            "PROVENANCE" => self.provenance_available,
            "TRUST_BOUNDARY" => self.trust_boundary_available,
            "TENANT_PRINCIPAL" => self.tenant_principal_available,
            "LIFECYCLE" => self.lifecycle_available,
            "DECISION_INFLUENCE" => self.decision_influence_available,
            // An unknown surface is not silently treated as absent.
            _ => true,
        }
    }
}

/// Build the additive metadata block.
pub fn build_memory_security_metadata(
    profile: &str,
    outcomes: &[MemoryScenarioOutcome],
    availability: MemorySurfaceAvailability,
) -> Result<MemorySecurityMetadata> {
    let mut counts = MemorySecurityCounts {
        scenarios: outcomes.len() as u32,
        ..MemorySecurityCounts::default()
    };
    for outcome in outcomes {
        counts.trials += outcome.trials_executed;
        counts.recall_items += outcome.recall_items;
        counts.violations += outcome.violations;
        match outcome.verdict.as_str() {
            "INCONCLUSIVE" => counts.inconclusive += 1,
            "ERROR" => counts.errors += 1,
            _ => {}
        }
    }

    let surfaces: BTreeMap<String, MemorySurfaceState> = MEMORY_SURFACES
        .iter()
        .map(|surface| {
            let touching: Vec<&MemoryScenarioOutcome> = outcomes
                .iter()
                .filter(|outcome| outcome.surface == *surface)
                .collect();

            let state = if touching.is_empty() {
                if availability.available(surface) {
                    MemorySurfaceState::NotTested
                } else {
                    MemorySurfaceState::NotApplicable
                }
            } else if touching
                .iter()
                .all(|outcome| matches!(outcome.verdict.as_str(), "INCONCLUSIVE" | "ERROR"))
            {
                // Looked at, and the evidence did not decide. Reporting this as
                // TESTED would let an undecided surface read as an exercised one.
                MemorySurfaceState::Inconclusive
            } else {
                MemorySurfaceState::Tested
            };

            ((*surface).to_owned(), state)
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
        "Memory was described from local fixtures and never written to any store.".to_owned(),
        "No Redis, PostgreSQL, vector database, SaaS memory service, remote MCP server or HTTP \
         provider was contacted."
            .to_owned(),
        "Every memory item, principal, tenant and namespace was synthetic; no customer memory \
         was read or written to demonstrate a boundary crossing."
            .to_owned(),
        "Lifecycle was evaluated against logical time declared by each scenario, not against a \
         wall clock."
            .to_owned(),
    ];
    if outcomes.iter().any(|outcome| outcome.synthetic) {
        limitations.push(
            "Some observations were synthetic and describe a reference agent, not a production one."
                .to_owned(),
        );
    }
    for (surface, state) in &surfaces {
        match state {
            MemorySurfaceState::NotTested => {
                limitations.push(format!("Surface {surface} was not exercised in this run."));
            }
            MemorySurfaceState::Inconclusive => {
                limitations.push(format!(
                    "Surface {surface} was exercised and the evidence did not decide it."
                ));
            }
            _ => {}
        }
    }

    let metadata = MemorySecurityMetadata {
        schema_id: MEMORY_SECURITY_METADATA_SCHEMA_ID.to_owned(),
        schema_version: "1".to_owned(),
        profile: profile.to_owned(),
        surfaces,
        counts,
        scenarios: outcomes
            .iter()
            .map(|outcome| MemorySecurityScenarioSummary {
                scenario_id: outcome.scenario_id.clone(),
                property_id: outcome.property_id.clone(),
                surface: outcome.surface.clone(),
                invariant: outcome.invariant.clone(),
                mode: outcome.mode.clone(),
                synthetic: outcome.synthetic,
                verdict: outcome.verdict.clone(),
                trials_planned: outcome.trials_planned,
                trials_executed: outcome.trials_executed,
                recall_items: outcome.recall_items,
                violations: outcome.violations,
            })
            .collect(),
        memory_trust_relation: MEMORY_TRUST_RELATION.to_owned(),
        availability_rule: AVAILABILITY_RULE.to_owned(),
        assurance_note,
        limitations,
        standards_note: STANDARDS_NOTE.to_owned(),
        scope_boundary_note: SCOPE_BOUNDARY_NOTE.to_owned(),
    };

    // The block is checked against its own rule before it is returned, so an
    // overstated note cannot reach a report by way of this builder.
    assert_bounded_claim(&serde_json::to_string(&metadata).map_err(|err| {
        crate::error::ProductError::internal(format!("memory-security metadata: {err}"))
    })?)?;

    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(surface: &str, verdict: &str) -> MemoryScenarioOutcome {
        MemoryScenarioOutcome {
            scenario_id: "MEMORY-LAB-001".to_owned(),
            property_id: "AGENT.MEMORY.PROVENANCE_INTEGRITY".to_owned(),
            surface: surface.to_owned(),
            invariant: "MEMORY_PROVENANCE_PRESENT".to_owned(),
            mode: "SIMULATED".to_owned(),
            synthetic: true,
            verdict: verdict.to_owned(),
            trials_planned: 3,
            trials_executed: 3,
            recall_items: 2,
            violations: u32::from(verdict == "FAIL"),
        }
    }

    #[test]
    fn the_five_surfaces_are_reported_separately_and_never_merged() {
        let metadata = build_memory_security_metadata(
            "memory-security-baseline-2026",
            &[outcome("PROVENANCE", "PASS")],
            MemorySurfaceAvailability::default(),
        )
        .expect("builds");

        assert_eq!(metadata.surfaces.len(), 5);
        assert_eq!(metadata.surfaces["PROVENANCE"], MemorySurfaceState::Tested);
        // The other four were never exercised and say so.
        for surface in ["TRUST_BOUNDARY", "TENANT_PRINCIPAL", "LIFECYCLE"] {
            assert_eq!(metadata.surfaces[surface], MemorySurfaceState::NotTested);
        }
    }

    #[test]
    fn not_tested_and_not_applicable_are_different_answers() {
        // A target with no namespaces genuinely has no namespace boundary; one
        // that has them and was never tested has a gap. Rendering them the same
        // would hide the gap behind a legitimate absence.
        let availability = MemorySurfaceAvailability {
            lifecycle_available: false,
            ..MemorySurfaceAvailability::default()
        };
        let metadata = build_memory_security_metadata(
            "memory-security-baseline-2026",
            &[outcome("PROVENANCE", "PASS")],
            availability,
        )
        .expect("builds");

        assert_eq!(
            metadata.surfaces["LIFECYCLE"],
            MemorySurfaceState::NotApplicable
        );
        assert_eq!(
            metadata.surfaces["TRUST_BOUNDARY"],
            MemorySurfaceState::NotTested
        );
        // Only the genuine gap is called out as a limitation.
        assert!(metadata
            .limitations
            .iter()
            .any(|note| note.contains("TRUST_BOUNDARY was not exercised")));
        assert!(!metadata
            .limitations
            .iter()
            .any(|note| note.contains("LIFECYCLE was not exercised")));
    }

    #[test]
    fn an_inconclusive_surface_is_neither_tested_nor_untested() {
        let metadata = build_memory_security_metadata(
            "memory-security-baseline-2026",
            &[outcome("PROVENANCE", "INCONCLUSIVE")],
            MemorySurfaceAvailability::default(),
        )
        .expect("builds");

        assert_eq!(
            metadata.surfaces["PROVENANCE"],
            MemorySurfaceState::Inconclusive
        );
        assert_eq!(metadata.assurance_note, BOUNDED_INCONCLUSIVE_NOTE);
        assert!(metadata
            .limitations
            .iter()
            .any(|note| note.contains("did not decide")));
    }

    #[test]
    fn an_inconclusive_result_is_never_rendered_as_a_pass() {
        let metadata = build_memory_security_metadata(
            "memory-security-baseline-2026",
            &[outcome("PROVENANCE", "PASS"), outcome("LIFECYCLE", "ERROR")],
            MemorySurfaceAvailability::default(),
        )
        .expect("builds");

        assert_ne!(metadata.assurance_note, BOUNDED_PASS_NOTE);
        assert_eq!(metadata.counts.errors, 1);
    }

    #[test]
    fn a_violation_dominates_the_assurance_note() {
        let metadata = build_memory_security_metadata(
            "memory-security-baseline-2026",
            &[
                outcome("PROVENANCE", "PASS"),
                outcome("TRUST_BOUNDARY", "FAIL"),
            ],
            MemorySurfaceAvailability::default(),
        )
        .expect("builds");

        assert_eq!(metadata.assurance_note, BOUNDED_VIOLATION_NOTE);
        assert_eq!(metadata.counts.violations, 1);
    }

    #[test]
    fn every_block_carries_the_relation_and_the_scope_boundary() {
        // A report read on its own must still say what a memory verdict means
        // and what it never examined.
        let metadata = build_memory_security_metadata(
            "memory-security-baseline-2026",
            &[outcome("PROVENANCE", "PASS")],
            MemorySurfaceAvailability::default(),
        )
        .expect("builds");

        assert!(metadata
            .memory_trust_relation
            .contains("stored_data != trusted_instruction"));
        assert!(metadata.availability_rule.contains("not authorization"));
        assert!(metadata
            .scope_boundary_note
            .contains("Retrieval-augmented generation"));
        assert!(metadata.standards_note.contains("not conformance"));
    }

    #[test]
    fn the_counts_record_zero_state_changes_and_zero_egress() {
        let metadata = build_memory_security_metadata(
            "memory-security-baseline-2026",
            &[outcome("PROVENANCE", "PASS")],
            MemorySurfaceAvailability::default(),
        )
        .expect("builds");

        assert_eq!(metadata.counts.state_changes, 0);
        assert_eq!(metadata.counts.external_egress_bytes, 0);
        assert_eq!(metadata.counts.recall_items, 2);
    }

    #[test]
    fn an_overstated_claim_is_refused_rather_than_softened() {
        for claim in [
            "the agent's memory is secure",
            "poisoning impossible under this design",
            "no memory poisoning was possible",
            "fully protected against ASI06",
            "ASI06 compliant",
        ] {
            assert!(
                assert_bounded_claim(claim).is_err(),
                "`{claim}` was allowed"
            );
        }

        // And the honest wording stays writable.
        assert_bounded_claim(BOUNDED_PASS_NOTE).expect("the approved wording is allowed");
        assert_bounded_claim(BOUNDED_VIOLATION_NOTE).expect("allowed");
        assert_bounded_claim(BOUNDED_INCONCLUSIVE_NOTE).expect("allowed");
    }

    #[test]
    fn the_builder_checks_its_own_output_against_the_claim_rule() {
        // The builder validates the block it is about to return, so an
        // overstated note cannot reach a report through this path even if a
        // future edit introduced one.
        let metadata = build_memory_security_metadata(
            "memory-security-baseline-2026",
            &[outcome("PROVENANCE", "PASS")],
            MemorySurfaceAvailability::default(),
        )
        .expect("builds");
        assert_bounded_claim(&serde_json::to_string(&metadata).expect("serializes"))
            .expect("the built block is bounded");
    }

    #[test]
    fn the_block_rejects_unknown_fields_on_the_way_back_in() {
        let mut value = serde_json::to_value(
            build_memory_security_metadata(
                "memory-security-baseline-2026",
                &[outcome("PROVENANCE", "PASS")],
                MemorySurfaceAvailability::default(),
            )
            .expect("builds"),
        )
        .expect("serializes");
        value["memory_store_url"] = serde_json::json!("redis://localhost:6379");

        assert!(serde_json::from_value::<MemorySecurityMetadata>(value).is_err());
    }
}
