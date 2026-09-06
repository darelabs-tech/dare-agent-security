//! Additive RAG and retrieval-security product metadata (Cycle 017).
//!
//! Built from existing v1 artifacts in the same style as the Cycle 012 Agentic,
//! Cycle 013 Prompt Injection, Cycle 014 Tool Security, Cycle 015 Identity
//! Security and Cycle 016 Memory Security blocks. No existing summary, findings
//! or coverage schema is modified.
//!
//! The reporting contract this module enforces is that a finite corpus result
//! is never rendered as universal retrieval security. The six surfaces —
//! retrieval authorization, document isolation, provenance, result integrity,
//! content trust and protected nondisclosure — are reported separately and
//! never merged, each is reported as tested, not tested, not applicable or
//! inconclusive, and the counts are always present so a reader can see how much
//! was actually exercised.
//!
//! Two further rules are enforced rather than documented: an inconclusive
//! result is never rendered as a pass, and the central relation this cycle
//! rests on — that a similarity match is not a permission — is carried in every
//! block, so a report read on its own still says what a retrieval verdict
//! means.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Whether a surface was exercised in this assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RagSurfaceState {
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

impl RagSurfaceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tested => "TESTED",
            Self::NotTested => "NOT_TESTED",
            Self::NotApplicable => "NOT_APPLICABLE",
            Self::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// The six retrieval-security surfaces, reported separately.
pub const RAG_SURFACES: [&str; 6] = [
    "RETRIEVAL_AUTHORIZATION",
    "DOCUMENT_ISOLATION",
    "PROVENANCE",
    "RESULT_INTEGRITY",
    "CONTENT_TRUST",
    "PROTECTED_NONDISCLOSURE",
];

/// Counts an operator needs in order to judge how much was actually validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagSecurityCounts {
    pub scenarios: u32,
    pub trials: u32,
    /// Queries issued across the run. Described from fixtures, never dispatched.
    pub queries: u32,
    /// Results returned across the run.
    pub results: u32,
    pub violations: u32,
    pub inconclusive: u32,
    pub errors: u32,
    /// Always zero. Cycle 017 indexes nothing.
    pub documents_indexed: u32,
    /// Always zero. Cycle 017 computes and compares no embedding.
    pub embeddings_computed: u32,
    /// Always zero. Cycle 017 changes no state and writes to no index.
    pub state_changes: u32,
    /// Always zero. Cycle 017 sends nothing anywhere.
    pub external_egress_bytes: u64,
}

/// One scenario's contribution to the product view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagSecurityScenarioSummary {
    pub scenario_id: String,
    pub property_id: String,
    /// One of the six surfaces. Never merged.
    pub surface: String,
    pub invariant: String,
    pub mode: String,
    pub synthetic: bool,
    pub verdict: String,
    pub trials_planned: u32,
    pub trials_executed: u32,
    pub queries: u32,
    pub results: u32,
    pub violations: u32,
}

/// Additive metadata block attached to the product view model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagSecurityMetadata {
    pub schema_id: String,
    pub schema_version: String,
    pub profile: String,
    /// Per-surface coverage. Each surface stands alone.
    pub surfaces: BTreeMap<String, RagSurfaceState>,
    pub counts: RagSecurityCounts,
    pub scenarios: Vec<RagSecurityScenarioSummary>,
    /// The relation every verdict is measured against.
    pub retrieval_trust_relation: String,
    /// The rule the ranking fixtures exist to state.
    pub ranking_rule: String,
    /// Bounded-claim statement. Never a universal security assertion.
    pub assurance_note: String,
    pub limitations: Vec<String>,
    /// Upstream attributions with their own statuses, never conformance claims.
    pub standards_note: String,
    /// What this block deliberately does not cover.
    pub scope_boundary_note: String,
}

pub const RAG_SECURITY_METADATA_SCHEMA_ID: &str =
    "https://darelabs.tech/schemas/product/additive/rag-security-metadata-2026";

/// Wording used whenever no violation was observed.
///
/// This is the approved phrasing, verbatim. It describes what was tested rather
/// than what is secure.
pub const BOUNDED_PASS_NOTE: &str =
    "No RAG/retrieval-security invariant violation was observed for the tested vectors under the \
     recorded conditions. This is a finite-corpus result and is not a claim that retrieval, \
     ranking or document handling holds in general.";

pub const BOUNDED_VIOLATION_NOTE: &str =
    "At least one deterministic RAG/retrieval-security invariant was violated under the recorded \
     conditions. Absence of further violations does not imply the remaining vectors are safe.";

pub const BOUNDED_INCONCLUSIVE_NOTE: &str =
    "Evidence was insufficient to decide at least one RAG/retrieval-security invariant. An \
     inconclusive result is not a pass and must not be reported as one.";

/// The relation the whole cycle rests on.
pub const RETRIEVAL_TRUST_RELATION: &str =
    "similarity_match != permission; retrieved_content != trusted_instruction; high_score != \
     safe_source. A document can be the most relevant thing in the index and still lie outside \
     the acting principal's authority.";

/// The corollary the ranking fixtures exist to state.
pub const RANKING_RULE: &str =
    "Score, embedding, similarity and ranking are evidence about ordering. None of them may \
     override policy, and no threshold on any of them decides a verdict here.";

/// How upstream sources are attributed.
///
/// LLM09 is an OWASP LLM Top 10 entry. Calling it an Agentic risk family, or
/// treating it as equivalent to an ASI category, would misdescribe both
/// taxonomies, so the note says what the mapping is and what it is not.
pub const STANDARDS_NOTE: &str =
    "OWASP LLM Top 10 2026, and LLM09:2026 Vector and Embedding Weaknesses in particular, are \
     used as risk taxonomy and context. LLM09 is an LLM Top 10 entry and is not an Agentic risk \
     family; no equivalence with ASI04, ASI06 or any other ASI category is claimed. Using a \
     similar vocabulary is not conformance, and nothing here is a certification against any \
     specification.";

/// What this cycle deliberately leaves to its neighbours.
///
/// Stated in the artifact rather than only in the docs, because a reader
/// holding one report has no other way to learn that instruction-following and
/// persisted memory were never examined, and might otherwise read "retrieval"
/// as covering them.
pub const SCOPE_BOUNDARY_NOTE: &str =
    "This block covers retrieval authorization, document isolation, provenance, result-set \
     integrity, content trust and protected nondisclosure only. Whether retrieved content acted \
     as an instruction remains Cycle 013's judgement; persisted memory remains Cycle 016's, and \
     retrieved content is not memory unless a separate memory event stores it. Token \
     verification, OAuth, OIDC and remote authorization are not evaluated here.";

/// Phrases that would overstate what a finite corpus can establish.
const FORBIDDEN_CLAIMS: [&str; 14] = [
    "rag secure",
    "rag is secure",
    "retrieval is secure",
    "vector database secure",
    "vector store secure",
    "no leakage possible",
    "leakage impossible",
    "no retrieval attack possible",
    "fully protected",
    "immune",
    "guaranteed secure",
    "no longer vulnerable",
    "llm09 compliant",
    "llm09 certified",
];

/// Refuse any rendered text that overstates the result.
pub fn assert_bounded_claim(text: &str) -> Result<()> {
    let lowered = text.to_lowercase();
    for forbidden in FORBIDDEN_CLAIMS {
        if lowered.contains(forbidden) {
            return Err(crate::error::ProductError::internal(format!(
                "refusing to render an unbounded RAG-security claim: {forbidden}"
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
pub struct RagScenarioOutcome {
    pub scenario_id: String,
    pub property_id: String,
    /// One of `RAG_SURFACES`.
    pub surface: String,
    pub invariant: String,
    pub mode: String,
    pub synthetic: bool,
    /// `PASS`, `FAIL`, `INCONCLUSIVE` or `ERROR`.
    pub verdict: String,
    pub trials_planned: u32,
    pub trials_executed: u32,
    pub queries: u32,
    pub results: u32,
    pub violations: u32,
}

/// Which surfaces the target actually has.
///
/// Kept explicit so "not applicable" is a stated fact about the target rather
/// than an inference from an empty result set. A single-tenant corpus with no
/// document ACL genuinely has no isolation boundary of that kind; one that has
/// them and was never tested is a gap, and the two must not render identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RagSurfaceAvailability {
    pub retrieval_authorization_available: bool,
    pub document_isolation_available: bool,
    pub provenance_available: bool,
    pub result_integrity_available: bool,
    pub content_trust_available: bool,
    pub protected_nondisclosure_available: bool,
}

impl Default for RagSurfaceAvailability {
    fn default() -> Self {
        Self {
            retrieval_authorization_available: true,
            document_isolation_available: true,
            provenance_available: true,
            result_integrity_available: true,
            content_trust_available: true,
            protected_nondisclosure_available: true,
        }
    }
}

impl RagSurfaceAvailability {
    fn available(&self, surface: &str) -> bool {
        match surface {
            "RETRIEVAL_AUTHORIZATION" => self.retrieval_authorization_available,
            "DOCUMENT_ISOLATION" => self.document_isolation_available,
            "PROVENANCE" => self.provenance_available,
            "RESULT_INTEGRITY" => self.result_integrity_available,
            "CONTENT_TRUST" => self.content_trust_available,
            "PROTECTED_NONDISCLOSURE" => self.protected_nondisclosure_available,
            // An unknown surface is not silently treated as absent.
            _ => true,
        }
    }
}

/// Build the additive metadata block.
pub fn build_rag_security_metadata(
    profile: &str,
    outcomes: &[RagScenarioOutcome],
    availability: RagSurfaceAvailability,
) -> Result<RagSecurityMetadata> {
    let mut counts = RagSecurityCounts {
        scenarios: outcomes.len() as u32,
        ..RagSecurityCounts::default()
    };
    for outcome in outcomes {
        counts.trials += outcome.trials_executed;
        counts.queries += outcome.queries;
        counts.results += outcome.results;
        counts.violations += outcome.violations;
        match outcome.verdict.as_str() {
            "INCONCLUSIVE" => counts.inconclusive += 1,
            "ERROR" => counts.errors += 1,
            _ => {}
        }
    }

    let surfaces: BTreeMap<String, RagSurfaceState> = RAG_SURFACES
        .iter()
        .map(|surface| {
            let touching: Vec<&RagScenarioOutcome> = outcomes
                .iter()
                .filter(|outcome| outcome.surface == *surface)
                .collect();

            let state = if touching.is_empty() {
                if availability.available(surface) {
                    RagSurfaceState::NotTested
                } else {
                    RagSurfaceState::NotApplicable
                }
            } else if touching
                .iter()
                .all(|outcome| matches!(outcome.verdict.as_str(), "INCONCLUSIVE" | "ERROR"))
            {
                // Looked at, and the evidence did not decide. Reporting this as
                // TESTED would let an undecided surface read as an exercised one.
                RagSurfaceState::Inconclusive
            } else {
                RagSurfaceState::Tested
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
        "Documents were described from local fixtures and were never indexed, embedded or \
         persisted."
            .to_owned(),
        "No Pinecone, Weaviate, Qdrant, Redis, PostgreSQL, OpenSearch, Elasticsearch, SaaS \
         retrieval API, production retriever, remote MCP server or HTTP provider was contacted."
            .to_owned(),
        "Every document, chunk, principal, tenant and collection was synthetic; no customer \
         corpus was read to demonstrate a boundary crossing."
            .to_owned(),
        "No embedding was computed or compared, and no score, ranking, similarity or reranker \
         decided any verdict; scores appear only as recorded evidence about ordering."
            .to_owned(),
    ];
    if outcomes.iter().any(|outcome| outcome.synthetic) {
        limitations.push(
            "Some observations were synthetic and describe a reference retriever, not a \
             production one."
                .to_owned(),
        );
    }
    for (surface, state) in &surfaces {
        match state {
            RagSurfaceState::NotTested => {
                limitations.push(format!("Surface {surface} was not exercised in this run."));
            }
            RagSurfaceState::Inconclusive => {
                limitations.push(format!(
                    "Surface {surface} was exercised and the evidence did not decide it."
                ));
            }
            _ => {}
        }
    }

    let metadata = RagSecurityMetadata {
        schema_id: RAG_SECURITY_METADATA_SCHEMA_ID.to_owned(),
        schema_version: "1".to_owned(),
        profile: profile.to_owned(),
        surfaces,
        counts,
        scenarios: outcomes
            .iter()
            .map(|outcome| RagSecurityScenarioSummary {
                scenario_id: outcome.scenario_id.clone(),
                property_id: outcome.property_id.clone(),
                surface: outcome.surface.clone(),
                invariant: outcome.invariant.clone(),
                mode: outcome.mode.clone(),
                synthetic: outcome.synthetic,
                verdict: outcome.verdict.clone(),
                trials_planned: outcome.trials_planned,
                trials_executed: outcome.trials_executed,
                queries: outcome.queries,
                results: outcome.results,
                violations: outcome.violations,
            })
            .collect(),
        retrieval_trust_relation: RETRIEVAL_TRUST_RELATION.to_owned(),
        ranking_rule: RANKING_RULE.to_owned(),
        assurance_note,
        limitations,
        standards_note: STANDARDS_NOTE.to_owned(),
        scope_boundary_note: SCOPE_BOUNDARY_NOTE.to_owned(),
    };

    // The block is checked against its own rule before it is returned, so an
    // overstated note cannot reach a report by way of this builder.
    assert_bounded_claim(&serde_json::to_string(&metadata).map_err(|err| {
        crate::error::ProductError::internal(format!("rag-security metadata: {err}"))
    })?)?;

    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(surface: &str, verdict: &str) -> RagScenarioOutcome {
        RagScenarioOutcome {
            scenario_id: "RAG-LAB-001".to_owned(),
            property_id: "AGENT.RAG.TENANT_DOCUMENT_ISOLATION".to_owned(),
            surface: surface.to_owned(),
            invariant: "RETRIEVAL_TENANT_BOUNDARY_PRESERVED".to_owned(),
            mode: "SIMULATED".to_owned(),
            synthetic: true,
            verdict: verdict.to_owned(),
            trials_planned: 3,
            trials_executed: 3,
            queries: 3,
            results: 9,
            violations: u32::from(verdict == "FAIL"),
        }
    }

    fn built(outcomes: &[RagScenarioOutcome]) -> RagSecurityMetadata {
        build_rag_security_metadata(
            "rag-security-baseline-2026",
            outcomes,
            RagSurfaceAvailability::default(),
        )
        .expect("builds")
    }

    #[test]
    fn the_six_surfaces_are_reported_separately_and_never_merged() {
        // One scenario exercised one surface. The other five must each appear
        // with their own state rather than being folded into a single number.
        let metadata = built(&[outcome("DOCUMENT_ISOLATION", "PASS")]);

        assert_eq!(metadata.surfaces.len(), 6);
        assert_eq!(
            metadata.surfaces["DOCUMENT_ISOLATION"],
            RagSurfaceState::Tested
        );
        for surface in RAG_SURFACES {
            if surface != "DOCUMENT_ISOLATION" {
                assert_eq!(
                    metadata.surfaces[surface],
                    RagSurfaceState::NotTested,
                    "{surface} did not report its own state"
                );
            }
        }
    }

    #[test]
    fn an_untested_surface_and_an_absent_one_do_not_render_identically() {
        // A target with no protected class has nothing to withhold; a target
        // that has one and was never tested has a gap. Rendering both the same
        // way would hide the gap behind an honest absence.
        let absent = build_rag_security_metadata(
            "rag-security-baseline-2026",
            &[outcome("DOCUMENT_ISOLATION", "PASS")],
            RagSurfaceAvailability {
                protected_nondisclosure_available: false,
                ..RagSurfaceAvailability::default()
            },
        )
        .expect("builds");

        assert_eq!(
            absent.surfaces["PROTECTED_NONDISCLOSURE"],
            RagSurfaceState::NotApplicable
        );
        assert_eq!(absent.surfaces["CONTENT_TRUST"], RagSurfaceState::NotTested);
    }

    #[test]
    fn an_inconclusive_surface_is_never_reported_as_tested() {
        // The difference that matters: something was looked at and the evidence
        // did not decide. Rendering that as TESTED would let an undecided
        // surface read as an exercised one.
        let metadata = built(&[outcome("PROVENANCE", "INCONCLUSIVE")]);
        assert_eq!(
            metadata.surfaces["PROVENANCE"],
            RagSurfaceState::Inconclusive
        );
        assert_eq!(metadata.assurance_note, BOUNDED_INCONCLUSIVE_NOTE);
        assert!(metadata.assurance_note.contains("is not a pass"));
    }

    #[test]
    fn a_violation_outranks_an_inconclusive_in_the_assurance_note() {
        // A run that both violated something and left something undecided is
        // first of all a run with a violation. Leading with the inconclusive
        // note would bury the finding.
        let metadata = built(&[
            outcome("DOCUMENT_ISOLATION", "FAIL"),
            outcome("PROVENANCE", "INCONCLUSIVE"),
        ]);
        assert_eq!(metadata.assurance_note, BOUNDED_VIOLATION_NOTE);
        assert_eq!(metadata.counts.violations, 1);
        assert_eq!(metadata.counts.inconclusive, 1);
    }

    #[test]
    fn every_block_carries_the_relation_a_verdict_is_measured_against() {
        let metadata = built(&[outcome("DOCUMENT_ISOLATION", "PASS")]);
        assert!(metadata
            .retrieval_trust_relation
            .contains("similarity_match != permission"));
        assert!(
            metadata.ranking_rule.contains("may not override policy")
                || metadata.ranking_rule.contains("override policy")
        );
    }

    #[test]
    fn the_standards_note_refuses_the_two_taxonomy_mistakes() {
        // LLM09 is an LLM Top 10 entry. Presenting it as an Agentic risk
        // family, or as equivalent to an ASI category, would misdescribe both
        // taxonomies to a reader who has only this block.
        let metadata = built(&[outcome("DOCUMENT_ISOLATION", "PASS")]);
        let note = &metadata.standards_note;
        assert!(note.contains("is not an Agentic risk family"));
        assert!(note.contains("no equivalence with ASI04, ASI06"));
        assert!(note.contains("not conformance"));
    }

    #[test]
    fn the_scope_boundary_names_the_cycles_either_side() {
        let metadata = built(&[outcome("DOCUMENT_ISOLATION", "PASS")]);
        let note = &metadata.scope_boundary_note;
        assert!(note.contains("Cycle 013"));
        assert!(note.contains("Cycle 016"));
        assert!(note.contains("retrieved content is not memory"));
        // Cycle 018's subject, explicitly excluded.
        assert!(note.contains("OAuth"));
    }

    #[test]
    fn the_zero_counts_are_present_rather_than_omitted() {
        // An absent count reads as "not measured". These are measured, and
        // they are zero.
        let metadata = built(&[outcome("DOCUMENT_ISOLATION", "PASS")]);
        assert_eq!(metadata.counts.documents_indexed, 0);
        assert_eq!(metadata.counts.embeddings_computed, 0);
        assert_eq!(metadata.counts.state_changes, 0);
        assert_eq!(metadata.counts.external_egress_bytes, 0);

        let rendered = serde_json::to_string(&metadata).expect("serializes");
        assert!(rendered.contains("\"embeddings_computed\":0"));
        assert!(rendered.contains("\"external_egress_bytes\":0"));
    }

    #[test]
    fn an_untested_surface_becomes_a_stated_limitation() {
        let metadata = built(&[outcome("DOCUMENT_ISOLATION", "PASS")]);
        assert!(metadata
            .limitations
            .iter()
            .any(|line| line.contains("Surface CONTENT_TRUST was not exercised")));
        assert!(metadata
            .limitations
            .iter()
            .any(|line| line.contains("No embedding was computed")));
    }

    #[test]
    fn an_unbounded_claim_is_refused_rather_than_rendered() {
        for hostile in [
            "the corpus is RAG secure",
            "no leakage possible",
            "vector store secure",
            "LLM09 compliant",
            "no retrieval attack possible",
        ] {
            assert!(
                assert_bounded_claim(hostile).is_err(),
                "`{hostile}` was allowed"
            );
        }

        assert!(assert_bounded_claim(BOUNDED_PASS_NOTE).is_ok());
        assert!(assert_bounded_claim(BOUNDED_VIOLATION_NOTE).is_ok());
        assert!(assert_bounded_claim(BOUNDED_INCONCLUSIVE_NOTE).is_ok());
        assert!(assert_bounded_claim(SCOPE_BOUNDARY_NOTE).is_ok());
        assert!(assert_bounded_claim(STANDARDS_NOTE).is_ok());
    }

    #[test]
    fn the_pass_note_describes_what_was_tested_rather_than_what_is_secure() {
        let metadata = built(&[outcome("DOCUMENT_ISOLATION", "PASS")]);
        assert_eq!(metadata.assurance_note, BOUNDED_PASS_NOTE);
        assert!(metadata.assurance_note.contains("for the tested vectors"));
        assert!(metadata.assurance_note.contains("finite-corpus result"));
        assert!(!metadata.assurance_note.to_lowercase().contains("is secure"));
    }
}
