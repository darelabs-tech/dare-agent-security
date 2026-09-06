//! Additive identity-security product metadata (Cycle 015).
//!
//! Built from existing v1 artifacts in the same style as the Cycle 012 Agentic,
//! Cycle 013 Prompt Injection and Cycle 014 Tool Security blocks. No existing
//! summary, findings or coverage schema is modified.
//!
//! The reporting contract this module enforces is that a finite corpus result is
//! never rendered as universal identity or authorization security. The five
//! surfaces — principal binding, delegation, privilege, tenant/resource and
//! authorization binding — are reported separately and never merged, each is
//! reported as tested, not tested or not applicable, and the counts are always
//! present so a reader can see how much was actually exercised.
//!
//! Two further rules are enforced rather than documented: an inconclusive
//! result is never rendered as a pass, and a draft or proposal upstream
//! (AuthZEN, COAZ) never becomes a conformance claim.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Whether a surface was exercised in this assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdentitySurfaceState {
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

impl IdentitySurfaceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tested => "TESTED",
            Self::NotTested => "NOT_TESTED",
            Self::NotApplicable => "NOT_APPLICABLE",
            Self::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// The five identity-security surfaces, reported separately.
pub const IDENTITY_SURFACES: [&str; 5] = [
    "PRINCIPAL_BINDING",
    "DELEGATION",
    "PRIVILEGE",
    "TENANT_RESOURCE",
    "AUTHORIZATION_BINDING",
];

/// Counts an operator needs in order to judge how much was actually validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySecurityCounts {
    pub scenarios: u32,
    pub trials: u32,
    /// Structured operations observed. Observed, never dispatched.
    pub operations: u32,
    /// Authorization decisions observed.
    pub authorization_decisions: u32,
    /// Deepest delegation exercised across the assessment.
    pub max_delegation_depth: u32,
    pub violations: u32,
    pub inconclusive: u32,
    pub errors: u32,
    /// Always zero. Cycle 015 changes no state.
    pub state_changes: u32,
    /// Always zero. Cycle 015 sends nothing anywhere.
    pub external_egress_bytes: u64,
}

/// One scenario's contribution to the product view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySecurityScenarioSummary {
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
    pub operations: u32,
    pub violations: u32,
}

/// Additive metadata block attached to the product view model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySecurityMetadata {
    pub schema_id: String,
    pub schema_version: String,
    pub profile: String,
    /// Per-surface coverage. Each surface stands alone.
    pub surfaces: BTreeMap<String, IdentitySurfaceState>,
    pub counts: IdentitySecurityCounts,
    pub scenarios: Vec<IdentitySecurityScenarioSummary>,
    /// The relation every verdict is measured against.
    pub authority_relation: String,
    /// The rule the credential fixtures exist to state.
    pub credential_rule: String,
    /// Bounded-claim statement. Never a universal security assertion.
    pub assurance_note: String,
    pub limitations: Vec<String>,
    /// Upstream attributions with their own statuses, never conformance claims.
    pub standards_note: String,
}

pub const IDENTITY_SECURITY_METADATA_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/product/additive/identity-security-metadata-2026";

/// Wording used whenever no violation was observed.
///
/// This is the approved phrasing, verbatim. It describes what was tested rather
/// than what is secure.
pub const BOUNDED_PASS_NOTE: &str =
    "No identity-security invariant violation was observed for the tested vectors under the \
     recorded conditions. This is a finite-corpus result and is not a claim that identity, \
     delegation, privilege or authorization handling holds in general.";

pub const BOUNDED_VIOLATION_NOTE: &str =
    "At least one deterministic identity-security invariant was violated under the recorded \
     conditions. Absence of further violations does not imply the remaining vectors are safe.";

pub const BOUNDED_INCONCLUSIVE_NOTE: &str =
    "Evidence was insufficient to decide at least one identity-security invariant. An \
     inconclusive result is not a pass and must not be reported as one.";

/// The relation the whole cycle rests on.
pub const AUTHORITY_RELATION: &str =
    "effective_authority <= delegated_or_source_authority_ceiling; authority may remain equal or \
     narrow through delegation and may never silently expand.";

/// The corollary the credential fixtures exist to state.
pub const CREDENTIAL_RULE: &str =
    "The presence of a service, workload or technical credential in the runtime is capability \
     availability and not delegated authority.";

/// How upstream sources are attributed.
pub const STANDARDS_NOTE: &str =
    "ASI03 is used as risk taxonomy and context. AuthZEN informs the authorization modelling and \
     COAZ work is referenced at its own draft status. Using similar concepts is not conformance, \
     and nothing here is a certification against any of them.";

/// Phrases that would overstate what a finite corpus can establish.
const FORBIDDEN_CLAIMS: [&str; 12] = [
    "identity secure",
    "authorization secure",
    "no privilege escalation possible",
    "fully protected",
    "immune",
    "guaranteed secure",
    "cannot be escalated",
    "cannot be impersonated",
    "no longer vulnerable",
    "authzen compliant",
    "coaz compliant",
    "authzen certified",
];

/// Refuse any rendered text that overstates the result.
pub fn assert_bounded_claim(text: &str) -> Result<()> {
    let lowered = text.to_lowercase();
    for forbidden in FORBIDDEN_CLAIMS {
        if lowered.contains(forbidden) {
            return Err(crate::error::ProductError::internal(format!(
                "refusing to render an unbounded identity-security claim: {forbidden}"
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
pub struct IdentityScenarioOutcome {
    pub scenario_id: String,
    pub property_id: String,
    /// One of `IDENTITY_SURFACES`.
    pub surface: String,
    pub invariant: String,
    pub mode: String,
    pub synthetic: bool,
    /// `PASS`, `FAIL`, `INCONCLUSIVE` or `ERROR`.
    pub verdict: String,
    pub trials_planned: u32,
    pub trials_executed: u32,
    pub operations: u32,
    pub authorization_decisions: u32,
    pub max_delegation_depth: u32,
    pub violations: u32,
}

/// Which surfaces the target actually has.
///
/// Kept explicit so "not applicable" is a stated fact about the target rather
/// than an inference from an empty result set. A single-tenant target genuinely
/// has no tenant boundary; a multi-tenant one that was never tested is a gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentitySurfaceAvailability {
    pub principal_binding_available: bool,
    pub delegation_available: bool,
    pub privilege_available: bool,
    pub tenant_resource_available: bool,
    pub authorization_binding_available: bool,
}

impl Default for IdentitySurfaceAvailability {
    fn default() -> Self {
        Self {
            principal_binding_available: true,
            delegation_available: true,
            privilege_available: true,
            tenant_resource_available: true,
            authorization_binding_available: true,
        }
    }
}

impl IdentitySurfaceAvailability {
    fn available(&self, surface: &str) -> bool {
        match surface {
            "PRINCIPAL_BINDING" => self.principal_binding_available,
            "DELEGATION" => self.delegation_available,
            "PRIVILEGE" => self.privilege_available,
            "TENANT_RESOURCE" => self.tenant_resource_available,
            "AUTHORIZATION_BINDING" => self.authorization_binding_available,
            // An unknown surface is not silently treated as absent.
            _ => true,
        }
    }
}

/// Build the additive metadata block.
pub fn build_identity_security_metadata(
    profile: &str,
    outcomes: &[IdentityScenarioOutcome],
    availability: IdentitySurfaceAvailability,
) -> Result<IdentitySecurityMetadata> {
    let mut counts = IdentitySecurityCounts {
        scenarios: outcomes.len() as u32,
        ..IdentitySecurityCounts::default()
    };
    for outcome in outcomes {
        counts.trials += outcome.trials_executed;
        counts.operations += outcome.operations;
        counts.authorization_decisions += outcome.authorization_decisions;
        counts.max_delegation_depth = counts
            .max_delegation_depth
            .max(outcome.max_delegation_depth);
        counts.violations += outcome.violations;
        match outcome.verdict.as_str() {
            "INCONCLUSIVE" => counts.inconclusive += 1,
            "ERROR" => counts.errors += 1,
            _ => {}
        }
    }

    let surfaces: BTreeMap<String, IdentitySurfaceState> = IDENTITY_SURFACES
        .iter()
        .map(|surface| {
            let touching: Vec<&IdentityScenarioOutcome> = outcomes
                .iter()
                .filter(|outcome| outcome.surface == *surface)
                .collect();

            let state = if touching.is_empty() {
                if availability.available(surface) {
                    IdentitySurfaceState::NotTested
                } else {
                    IdentitySurfaceState::NotApplicable
                }
            } else if touching
                .iter()
                .all(|outcome| matches!(outcome.verdict.as_str(), "INCONCLUSIVE" | "ERROR"))
            {
                // Looked at, and the evidence did not decide. Reporting this as
                // TESTED would let an undecided surface read as an exercised one.
                IdentitySurfaceState::Inconclusive
            } else {
                IdentitySurfaceState::Tested
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
        "Structured operations were observed and never dispatched; no operation was performed."
            .to_owned(),
        "No identity provider, OAuth server, PDP, AuthZEN endpoint or MCP server was contacted, \
         and no token was parsed or validated."
            .to_owned(),
        "Every principal, tenant, resource and credential context was synthetic; no real tenant \
         data was accessed to demonstrate a boundary crossing."
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
            IdentitySurfaceState::NotTested => {
                limitations.push(format!("Surface {surface} was not exercised in this run."));
            }
            IdentitySurfaceState::Inconclusive => {
                limitations.push(format!(
                    "Surface {surface} was exercised and the evidence did not decide it."
                ));
            }
            _ => {}
        }
    }

    let metadata = IdentitySecurityMetadata {
        schema_id: IDENTITY_SECURITY_METADATA_SCHEMA_ID.to_owned(),
        schema_version: "1".to_owned(),
        profile: profile.to_owned(),
        surfaces,
        counts,
        scenarios: outcomes
            .iter()
            .map(|outcome| IdentitySecurityScenarioSummary {
                scenario_id: outcome.scenario_id.clone(),
                property_id: outcome.property_id.clone(),
                surface: outcome.surface.clone(),
                invariant: outcome.invariant.clone(),
                mode: outcome.mode.clone(),
                synthetic: outcome.synthetic,
                verdict: outcome.verdict.clone(),
                trials_planned: outcome.trials_planned,
                trials_executed: outcome.trials_executed,
                operations: outcome.operations,
                violations: outcome.violations,
            })
            .collect(),
        authority_relation: AUTHORITY_RELATION.to_owned(),
        credential_rule: CREDENTIAL_RULE.to_owned(),
        assurance_note,
        limitations,
        standards_note: STANDARDS_NOTE.to_owned(),
    };

    // The block is checked as a whole, so a limitation or note added later
    // cannot slip an unbounded phrase past the gate.
    assert_bounded_claim(&serde_json::to_string(&metadata).map_err(|err| {
        crate::error::ProductError::internal(format!(
            "identity metadata is not serializable: {err}"
        ))
    })?)?;

    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(surface: &str, verdict: &str) -> IdentityScenarioOutcome {
        IdentityScenarioOutcome {
            scenario_id: format!("IDENTITY-LAB-{surface}"),
            property_id: "AGENT.IDENTITY.PRINCIPAL_BINDING".to_owned(),
            surface: surface.to_owned(),
            invariant: "INITIATING_PRINCIPAL_PRESERVED".to_owned(),
            mode: "SIMULATED".to_owned(),
            synthetic: true,
            verdict: verdict.to_owned(),
            trials_planned: 3,
            trials_executed: 1,
            operations: 1,
            authorization_decisions: 1,
            max_delegation_depth: 1,
            violations: if verdict == "FAIL" { 1 } else { 0 },
        }
    }

    #[test]
    fn the_five_surfaces_are_reported_separately_and_never_merged() {
        let metadata = build_identity_security_metadata(
            "identity-security-baseline-2026",
            &[outcome("PRINCIPAL_BINDING", "PASS")],
            IdentitySurfaceAvailability::default(),
        )
        .expect("builds");

        assert_eq!(metadata.surfaces.len(), 5);
        assert_eq!(
            metadata.surfaces["PRINCIPAL_BINDING"],
            IdentitySurfaceState::Tested
        );
        for untested in [
            "DELEGATION",
            "PRIVILEGE",
            "TENANT_RESOURCE",
            "AUTHORIZATION_BINDING",
        ] {
            assert_eq!(
                metadata.surfaces[untested],
                IdentitySurfaceState::NotTested,
                "{untested}"
            );
        }
    }

    #[test]
    fn an_undecided_surface_is_inconclusive_and_not_tested_or_passing() {
        // "We looked and could not tell" and "we never looked" are different
        // answers, and neither of them is "it held".
        let metadata = build_identity_security_metadata(
            "identity-security-baseline-2026",
            &[outcome("DELEGATION", "INCONCLUSIVE")],
            IdentitySurfaceAvailability::default(),
        )
        .expect("builds");

        assert_eq!(
            metadata.surfaces["DELEGATION"],
            IdentitySurfaceState::Inconclusive
        );
        assert_eq!(metadata.assurance_note, BOUNDED_INCONCLUSIVE_NOTE);
        assert!(metadata
            .limitations
            .iter()
            .any(|line| line.contains("did not decide")));
    }

    #[test]
    fn an_absent_surface_is_not_applicable_rather_than_untested() {
        let metadata = build_identity_security_metadata(
            "identity-security-baseline-2026",
            &[outcome("PRINCIPAL_BINDING", "PASS")],
            IdentitySurfaceAvailability {
                tenant_resource_available: false,
                ..IdentitySurfaceAvailability::default()
            },
        )
        .expect("builds");

        assert_eq!(
            metadata.surfaces["TENANT_RESOURCE"],
            IdentitySurfaceState::NotApplicable
        );
        assert!(!metadata
            .limitations
            .iter()
            .any(|line| line.contains("Surface TENANT_RESOURCE was not exercised")));
    }

    #[test]
    fn a_violation_selects_the_violation_note_over_everything_else() {
        let metadata = build_identity_security_metadata(
            "identity-security-baseline-2026",
            &[
                outcome("PRINCIPAL_BINDING", "FAIL"),
                outcome("DELEGATION", "INCONCLUSIVE"),
            ],
            IdentitySurfaceAvailability::default(),
        )
        .expect("builds");

        assert_eq!(metadata.assurance_note, BOUNDED_VIOLATION_NOTE);
        assert_eq!(metadata.counts.violations, 1);
        assert_eq!(metadata.counts.inconclusive, 1);
    }

    #[test]
    fn the_counts_pin_zero_state_change_and_zero_egress() {
        let metadata = build_identity_security_metadata(
            "identity-security-baseline-2026",
            &[outcome("PRIVILEGE", "PASS")],
            IdentitySurfaceAvailability::default(),
        )
        .expect("builds");
        assert_eq!(metadata.counts.state_changes, 0);
        assert_eq!(metadata.counts.external_egress_bytes, 0);
    }

    #[test]
    fn the_block_carries_the_authority_relation_and_the_credential_rule() {
        let metadata = build_identity_security_metadata(
            "identity-security-baseline-2026",
            &[outcome("PRIVILEGE", "PASS")],
            IdentitySurfaceAvailability::default(),
        )
        .expect("builds");
        assert!(metadata
            .authority_relation
            .contains("effective_authority <= delegated_or_source_authority_ceiling"));
        assert!(metadata.credential_rule.contains("not delegated authority"));
        assert!(metadata.standards_note.contains("not conformance"));
    }

    #[test]
    fn an_unbounded_claim_is_refused() {
        for claim in [
            "The target is Identity Secure.",
            "No Privilege Escalation Possible.",
            "Fully Protected.",
            "Immune to confused-deputy attacks.",
            "DARE is AuthZEN compliant.",
            "COAZ compliant.",
        ] {
            assert!(assert_bounded_claim(claim).is_err(), "{claim}");
        }
        assert_bounded_claim(BOUNDED_PASS_NOTE).expect("the approved wording is allowed");
        assert_bounded_claim(BOUNDED_VIOLATION_NOTE).expect("the approved wording is allowed");
        assert_bounded_claim(BOUNDED_INCONCLUSIVE_NOTE).expect("the approved wording is allowed");
    }

    #[test]
    fn the_pass_note_describes_what_was_tested_rather_than_what_is_secure() {
        assert!(BOUNDED_PASS_NOTE.starts_with(
            "No identity-security invariant violation was observed for the tested vectors under \
             the recorded conditions."
        ));
        assert!(BOUNDED_PASS_NOTE.contains("is not a claim"));
    }

    #[test]
    fn the_block_is_deterministic() {
        let outcomes = [outcome("PRIVILEGE", "PASS"), outcome("DELEGATION", "FAIL")];
        let first = build_identity_security_metadata(
            "identity-security-baseline-2026",
            &outcomes,
            IdentitySurfaceAvailability::default(),
        )
        .expect("builds");
        let second = build_identity_security_metadata(
            "identity-security-baseline-2026",
            &outcomes,
            IdentitySurfaceAvailability::default(),
        )
        .expect("builds");
        assert_eq!(first, second);
    }
}
