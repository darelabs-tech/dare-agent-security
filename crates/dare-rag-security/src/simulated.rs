//! Simulated adapter: deterministic scenario-derived observations.
//!
//! There is no model here and no retriever. Given a scenario and a trial index,
//! this stages the observations a reference retriever with the scenario's
//! declared [`ReferenceBehavior`] would have produced, and the same inputs
//! always yield byte-identical output.
//!
//! Two rules keep the simulation honest:
//!
//! - **every value is derived from the scenario.** Document ids, chunk ids,
//!   tenants, owners, collections and classifications all come from what the
//!   fixture declares. The adapter never invents an identifier to make a
//!   violation appear, so a staged violation is one the fixture really
//!   describes. A behaviour the scenario cannot stage from its own declarations
//!   is refused rather than approximated — an approximation would be a finding
//!   about a document nobody wrote.
//! - **behaviour is not verdict.** A `ReferenceBehavior` says what the
//!   retriever did; whether that is a violation is the evaluator's decision,
//!   taken from the same typed events a replayed trace would produce.

use serde::{Deserialize, Serialize};

use crate::document::Document;
use crate::error::{RagSecurityError, Result};
use crate::harness::{
    HarnessAdapter, HarnessMode, RawCandidateSet, RawFilterDecision, RawHarnessError, RawInfluence,
    RawResultSet, RawTrialOutput, TrialRequest,
};
use crate::model::{RagSecurityScenario, ReferenceBehavior};
use crate::observation::{HarnessErrorKind, InfluenceTarget};
use crate::query::RankedResult;
use crate::source::DocumentTrustClass;

/// Deterministic staging of a reference retriever's behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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
        // A scenario with no lab spec says nothing about how a reference
        // retriever behaved, and guessing a behaviour would fabricate the
        // observation.
        let lab = request.scenario.lab.as_ref().ok_or_else(|| {
            RagSecurityError::invalid(format!(
                "scenario `{}` declares no lab spec, so no reference behaviour can be staged",
                request.scenario.id
            ))
        })?;
        stage(request.scenario, lab.behavior_for(request.trial_index))
    }
}

/// Build the observations for one behaviour.
pub fn stage(
    scenario: &RagSecurityScenario,
    behavior: ReferenceBehavior,
) -> Result<RawTrialOutput> {
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
        // Deliberately empty. The channel a contract needs is absent, so the
        // evaluator must say INCONCLUSIVE rather than PASS.
        return Ok(RawTrialOutput::default());
    }

    let mut output = compliant(scenario)?;

    match behavior {
        B::Compliant | B::NoRelevantObservation | B::HarnessFailure => {}
        B::CrossPrincipalResult => return_foreign(scenario, &mut output, Axis::Principal)?,
        B::CrossTenantResult => return_foreign(scenario, &mut output, Axis::Tenant)?,
        B::CrossCollectionResult => return_foreign(scenario, &mut output, Axis::Collection)?,
        B::UnauthorizedDocumentResult => return_unauthorized(scenario, &mut output)?,
        B::MetadataFilterBypassed => bypass_filter(scenario, &mut output)?,
        B::ProtectedDocumentReturned => return_protected(scenario, &mut output)?,
        B::ProvenanceDetached => detach_provenance(scenario, &mut output)?,
        B::ChunkReboundToAnotherDocument => rebind_chunk(scenario, &mut output)?,
        B::NonCandidateResultInjected => inject_non_candidate(scenario, &mut output)?,
        B::TopKExceeded => exceed_top_k(scenario, &mut output)?,
        B::UntrustedContentPromoted => promote_untrusted(scenario, &mut output)?,
        B::RetrievedWithoutPromotion => record_non_promotion(scenario, &mut output)?,
        B::FallbackWithinAuthority => fallback_inside(scenario, &mut output)?,
        B::FallbackWidenedAuthority => fallback_widened(scenario, &mut output)?,
        B::MultipleIndependentViolations => {
            // Three independently true violations in one trial, so the
            // evaluator has to report all of them rather than the first.
            return_foreign(scenario, &mut output, Axis::Tenant)?;
            rebind_chunk(scenario, &mut output)?;
            return_protected(scenario, &mut output)?;
        }
    }

    Ok(output)
}

/// Which axis a staged result crosses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Axis {
    Principal,
    Tenant,
    Collection,
}

/// The observations of a retriever that stayed inside everything it was granted.
fn compliant(scenario: &RagSecurityScenario) -> Result<RawTrialOutput> {
    let mut output = RawTrialOutput {
        queries: scenario.queries.clone(),
        ..RawTrialOutput::default()
    };

    for query in &scenario.queries {
        // The approved candidate set, as the scenario declares it.
        if let Some(set) = scenario.candidate_set(&query.query_id) {
            output.candidate_sets.push(RawCandidateSet {
                query_id: set.query_id.clone(),
                candidates: set.candidates.clone(),
            });
        }

        // A compliant retriever returns candidates that are inside every
        // boundary, ordered by declared score, and never more than asked for.
        let mut admissible: Vec<&crate::query::Candidate> = scenario
            .candidate_set(&query.query_id)
            .map(|set| {
                set.candidates
                    .iter()
                    .filter(|candidate| {
                        scenario
                            .store
                            .document(&candidate.document_id)
                            .map(|document| is_fully_authorized(scenario, document, query))
                            .unwrap_or(false)
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Deterministic ordering: declared score descending, chunk id as the
        // tie-break so the result is stable without appealing to similarity.
        admissible.sort_by(|left, right| {
            right
                .score
                .unwrap_or(0.0)
                .partial_cmp(&left.score.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.chunk_id.cmp(&right.chunk_id))
        });
        admissible.truncate(query.requested_top_k as usize);

        let results: Vec<RankedResult> = admissible
            .iter()
            .enumerate()
            .map(|(index, candidate)| RankedResult {
                chunk_id: candidate.chunk_id.clone(),
                document_id: candidate.document_id.clone(),
                rank: index as u32,
                score: candidate.score,
                from_fallback: false,
            })
            .collect();

        // Filter decisions for every candidate, admitted or not: a decision
        // recorded only for admitted documents would make a bypass invisible.
        if let Some(set) = scenario.candidate_set(&query.query_id) {
            for candidate in &set.candidates {
                let admitted = results
                    .iter()
                    .any(|result| result.chunk_id == candidate.chunk_id);
                output.filter_decisions.push(RawFilterDecision {
                    query_id: query.query_id.clone(),
                    document_id: candidate.document_id.clone(),
                    admitted,
                });
            }
        }

        output.result_sets.push(RawResultSet {
            query_id: query.query_id.clone(),
            results,
            used_fallback: false,
        });
    }

    // Returning content and changing nothing is a positive fact, and the only
    // evidence on which a no-promotion PASS can rest.
    for set in &output.result_sets {
        for result in &set.results {
            if let Some(document) = scenario.store.document(&result.document_id) {
                output.influences.push(RawInfluence {
                    document_id: document.document_id.clone(),
                    chunk_id: Some(result.chunk_id.clone()),
                    target: InfluenceTarget::Objective,
                    field: None,
                    baseline_value: Some(scenario.objective.authorized_objective_id.clone()),
                    observed_value: Some(scenario.objective.authorized_objective_id.clone()),
                    changed: false,
                    treated_as_trust_class: Some(scenario.policy.effective_trust_ceiling(document)),
                });
            }
        }
    }

    Ok(output)
}

/// Whether a document satisfies every boundary the scenario declares.
fn is_fully_authorized(
    scenario: &RagSecurityScenario,
    document: &Document,
    query: &crate::query::QueryRequest,
) -> bool {
    let policy = &scenario.policy;
    scenario.context.same_tenant(&document.tenant_id)
        && policy.permits_tenant(&document.tenant_id)
        && policy.permits_collection(&document.collection_id)
        && query.collection_ids.contains(&document.collection_id)
        && policy.permits_document(&document.document_id)
        && (scenario
            .context
            .owned_by_acting(&document.owner_principal_id)
            || policy.permits_owner(&document.owner_principal_id))
        && !document.classification.exceeds(policy.max_classification)
        && !policy.protected.protects(document)
        && document.is_retrievable()
        && query.filter.unsatisfied(&document.metadata).is_empty()
        && policy
            .metadata_filter
            .unsatisfied(&document.metadata)
            .is_empty()
}

/// The first chunk whose document differs from the acting context on one axis.
fn foreign_chunk(
    scenario: &RagSecurityScenario,
    axis: Axis,
) -> Result<(&crate::document::Chunk, &Document)> {
    let context = &scenario.context;
    for chunk in &scenario.store.chunks {
        let Some(document) = scenario.store.document(&chunk.document_id) else {
            continue;
        };
        let crosses = match axis {
            Axis::Principal => {
                !context.owned_by_acting(&document.owner_principal_id)
                    && !scenario.policy.permits_owner(&document.owner_principal_id)
            }
            Axis::Tenant => !context.same_tenant(&document.tenant_id),
            Axis::Collection => !context.addresses_collection(&document.collection_id),
        };
        if crosses {
            return Ok((chunk, document));
        }
    }
    Err(RagSecurityError::invalid(format!(
        "scenario `{}` declares no document outside the acting {}, so that crossing cannot be \
         staged without inventing one",
        scenario.id,
        match axis {
            Axis::Principal => "principal",
            Axis::Tenant => "tenant",
            Axis::Collection => "collection",
        }
    )))
}

/// Append one result to every result set, at the next free rank.
fn append_result(output: &mut RawTrialOutput, result: RankedResult) {
    if output.result_sets.is_empty() {
        return;
    }
    for set in &mut output.result_sets {
        if set
            .results
            .iter()
            .any(|existing| existing.chunk_id == result.chunk_id)
        {
            continue;
        }
        let mut appended = result.clone();
        appended.rank = set.results.len() as u32;
        set.results.push(appended);
    }
}

fn return_foreign(
    scenario: &RagSecurityScenario,
    output: &mut RawTrialOutput,
    axis: Axis,
) -> Result<()> {
    let (chunk, document) = foreign_chunk(scenario, axis)?;
    append_result(
        output,
        RankedResult {
            chunk_id: chunk.chunk_id.clone(),
            document_id: document.document_id.clone(),
            rank: 0,
            // A high score, deliberately: the point of the cycle is that this
            // changes nothing about the verdict.
            score: Some(0.99),
            from_fallback: false,
        },
    );
    Ok(())
}

fn return_unauthorized(scenario: &RagSecurityScenario, output: &mut RawTrialOutput) -> Result<()> {
    let policy = &scenario.policy;
    let (chunk, document) = scenario
        .store
        .chunks
        .iter()
        .find_map(|chunk| {
            let document = scenario.store.document(&chunk.document_id)?;
            let unauthorized = !policy.permits_document(&document.document_id)
                || document.classification.exceeds(policy.max_classification);
            unauthorized.then_some((chunk, document))
        })
        .ok_or_else(|| {
            RagSecurityError::invalid(format!(
                "scenario `{}` declares no document outside the allowed set, so an unauthorized \
                 return cannot be staged",
                scenario.id
            ))
        })?;

    append_result(
        output,
        RankedResult {
            chunk_id: chunk.chunk_id.clone(),
            document_id: document.document_id.clone(),
            rank: 0,
            score: Some(0.97),
            from_fallback: false,
        },
    );
    Ok(())
}

fn bypass_filter(scenario: &RagSecurityScenario, output: &mut RawTrialOutput) -> Result<()> {
    // A document that fails a mandatory clause, admitted anyway.
    let query = scenario.queries.first().ok_or_else(|| {
        RagSecurityError::invalid(format!("scenario `{}` declares no query", scenario.id))
    })?;

    let document = scenario
        .store
        .documents
        .iter()
        .find(|document| !query.filter.unsatisfied(&document.metadata).is_empty())
        .ok_or_else(|| {
            RagSecurityError::invalid(format!(
                "scenario `{}` declares no document that fails its filter, so a bypass cannot be \
                 staged",
                scenario.id
            ))
        })?;

    // Flip the recorded decision to admitted; the unsatisfied fields are
    // recomputed from the corpus during normalization, so the contradiction
    // between "admitted" and "fails the clause" is what becomes visible.
    let mut recorded = false;
    for decision in &mut output.filter_decisions {
        if decision.document_id == document.document_id {
            decision.admitted = true;
            recorded = true;
        }
    }
    if !recorded {
        output.filter_decisions.push(RawFilterDecision {
            query_id: query.query_id.clone(),
            document_id: document.document_id.clone(),
            admitted: true,
        });
    }
    Ok(())
}

fn return_protected(scenario: &RagSecurityScenario, output: &mut RawTrialOutput) -> Result<()> {
    let (chunk, document) = scenario
        .store
        .chunks
        .iter()
        .find_map(|chunk| {
            let document = scenario.store.document(&chunk.document_id)?;
            scenario
                .policy
                .protected
                .protects(document)
                .then_some((chunk, document))
        })
        .ok_or_else(|| {
            RagSecurityError::invalid(format!(
                "scenario `{}` declares no protected document, so a disclosure cannot be staged",
                scenario.id
            ))
        })?;

    append_result(
        output,
        RankedResult {
            chunk_id: chunk.chunk_id.clone(),
            document_id: document.document_id.clone(),
            rank: 0,
            // Highest score in the set. Protected nondisclosure is independent
            // of ranking, and staging it this way makes that concrete.
            score: Some(1.0),
            from_fallback: false,
        },
    );
    Ok(())
}

fn detach_provenance(scenario: &RagSecurityScenario, output: &mut RawTrialOutput) -> Result<()> {
    // A returned chunk whose document carries no machine-readable provenance.
    // Staged by returning a document the fixture declares that way; the
    // adapter never edits the corpus.
    let (chunk, document) = scenario
        .store
        .chunks
        .iter()
        .find_map(|chunk| {
            let document = scenario.store.document(&chunk.document_id)?;
            (!document.has_machine_readable_provenance()).then_some((chunk, document))
        })
        .ok_or_else(|| {
            RagSecurityError::invalid(format!(
                "scenario `{}` declares no document without machine-readable provenance, so a \
                 detachment cannot be staged",
                scenario.id
            ))
        })?;

    append_result(
        output,
        RankedResult {
            chunk_id: chunk.chunk_id.clone(),
            document_id: document.document_id.clone(),
            rank: 0,
            score: Some(0.80),
            from_fallback: false,
        },
    );
    Ok(())
}

fn rebind_chunk(scenario: &RagSecurityScenario, output: &mut RawTrialOutput) -> Result<()> {
    // A chunk returned as though it belonged to a different, more trusted
    // document. The chunk and both documents are declared; only the claim moves.
    let chunk = scenario.store.chunks.first().ok_or_else(|| {
        RagSecurityError::invalid(format!("scenario `{}` declares no chunk", scenario.id))
    })?;
    let other = scenario
        .store
        .documents
        .iter()
        .find(|document| document.document_id != chunk.document_id)
        .ok_or_else(|| {
            RagSecurityError::invalid(format!(
                "scenario `{}` declares one document only, so a rebinding cannot be staged",
                scenario.id
            ))
        })?;

    let mut rebound = false;
    for set in &mut output.result_sets {
        for result in &mut set.results {
            if result.chunk_id == chunk.chunk_id {
                result.document_id = other.document_id.clone();
                rebound = true;
            }
        }
    }
    if !rebound {
        append_result(
            output,
            RankedResult {
                chunk_id: chunk.chunk_id.clone(),
                document_id: other.document_id.clone(),
                rank: 0,
                score: Some(0.88),
                from_fallback: false,
            },
        );
    }
    Ok(())
}

fn inject_non_candidate(scenario: &RagSecurityScenario, output: &mut RawTrialOutput) -> Result<()> {
    let query = scenario.queries.first().ok_or_else(|| {
        RagSecurityError::invalid(format!("scenario `{}` declares no query", scenario.id))
    })?;
    let approved = scenario
        .candidate_set(&query.query_id)
        .map(|set| set.chunk_ids())
        .unwrap_or_default();

    let chunk = scenario
        .store
        .chunks
        .iter()
        .find(|chunk| !approved.contains(chunk.chunk_id.as_str()))
        .ok_or_else(|| {
            RagSecurityError::invalid(format!(
                "scenario `{}` approves every declared chunk as a candidate, so an injection \
                 cannot be staged",
                scenario.id
            ))
        })?;

    append_result(
        output,
        RankedResult {
            chunk_id: chunk.chunk_id.clone(),
            document_id: chunk.document_id.clone(),
            rank: 0,
            score: Some(0.95),
            from_fallback: false,
        },
    );
    Ok(())
}

fn exceed_top_k(scenario: &RagSecurityScenario, output: &mut RawTrialOutput) -> Result<()> {
    let allowed = scenario.policy.top_k.max_top_k as usize;

    // Pad each result set past the ceiling using declared chunks only.
    for set in &mut output.result_sets {
        for chunk in &scenario.store.chunks {
            if set.results.len() > allowed {
                break;
            }
            if set
                .results
                .iter()
                .any(|result| result.chunk_id == chunk.chunk_id)
            {
                continue;
            }
            let rank = set.results.len() as u32;
            set.results.push(RankedResult {
                chunk_id: chunk.chunk_id.clone(),
                document_id: chunk.document_id.clone(),
                rank,
                score: Some(0.10),
                from_fallback: false,
            });
        }
    }

    if output
        .result_sets
        .iter()
        .all(|set| set.results.len() <= allowed)
    {
        return Err(RagSecurityError::invalid(format!(
            "scenario `{}` declares too few chunks to exceed its own top-k ceiling",
            scenario.id
        )));
    }
    Ok(())
}

fn promote_untrusted(scenario: &RagSecurityScenario, output: &mut RawTrialOutput) -> Result<()> {
    // A document whose effective ceiling is below policy authority, treated as
    // policy-authoritative and allowed to change the objective.
    let document = scenario
        .store
        .documents
        .iter()
        .find(|document| {
            scenario.policy.effective_trust_ceiling(document).rank()
                < DocumentTrustClass::TrustedPolicy.rank()
        })
        .ok_or_else(|| {
            RagSecurityError::invalid(format!(
                "scenario `{}` declares no document below policy authority, so a promotion \
                 cannot be staged",
                scenario.id
            ))
        })?;

    // Ensure it was actually returned, so the promotion attaches to something
    // the trial observed.
    if let Some(chunk) = scenario
        .store
        .chunks
        .iter()
        .find(|chunk| chunk.document_id == document.document_id)
    {
        append_result(
            output,
            RankedResult {
                chunk_id: chunk.chunk_id.clone(),
                document_id: document.document_id.clone(),
                rank: 0,
                score: Some(0.93),
                from_fallback: false,
            },
        );
    }

    output.influences.retain(|influence| influence.changed);
    output.influences.push(RawInfluence {
        document_id: document.document_id.clone(),
        chunk_id: None,
        target: InfluenceTarget::Objective,
        field: None,
        baseline_value: Some(scenario.objective.authorized_objective_id.clone()),
        observed_value: Some(format!(
            "{}-altered",
            scenario.objective.authorized_objective_id
        )),
        changed: true,
        treated_as_trust_class: Some(DocumentTrustClass::TrustedPolicy),
    });
    Ok(())
}

fn record_non_promotion(scenario: &RagSecurityScenario, output: &mut RawTrialOutput) -> Result<()> {
    // Untrusted content returned and explicitly recorded as changing nothing.
    // This is the positive evidence a no-promotion PASS rests on.
    let document = scenario
        .store
        .documents
        .iter()
        .find(|document| document.trust_class == DocumentTrustClass::Untrusted)
        .ok_or_else(|| {
            RagSecurityError::invalid(format!(
                "scenario `{}` declares no untrusted document, so non-promotion cannot be shown",
                scenario.id
            ))
        })?;

    if let Some(chunk) = scenario
        .store
        .chunks
        .iter()
        .find(|chunk| chunk.document_id == document.document_id)
    {
        append_result(
            output,
            RankedResult {
                chunk_id: chunk.chunk_id.clone(),
                document_id: document.document_id.clone(),
                rank: 0,
                score: Some(0.71),
                from_fallback: false,
            },
        );
    }

    output.influences.push(RawInfluence {
        document_id: document.document_id.clone(),
        chunk_id: None,
        target: InfluenceTarget::Objective,
        field: None,
        baseline_value: Some(scenario.objective.authorized_objective_id.clone()),
        observed_value: Some(scenario.objective.authorized_objective_id.clone()),
        changed: false,
        treated_as_trust_class: Some(document.trust_class),
    });
    Ok(())
}

fn fallback_inside(scenario: &RagSecurityScenario, output: &mut RawTrialOutput) -> Result<()> {
    // A broadened retry that returns a document already inside every boundary.
    let query = scenario.queries.first().ok_or_else(|| {
        RagSecurityError::invalid(format!("scenario `{}` declares no query", scenario.id))
    })?;
    let (chunk, _document) = scenario
        .store
        .chunks
        .iter()
        .find_map(|chunk| {
            let document = scenario.store.document(&chunk.document_id)?;
            is_fully_authorized(scenario, document, query).then_some((chunk, document))
        })
        .ok_or_else(|| {
            RagSecurityError::invalid(format!(
                "scenario `{}` declares no fully authorized document, so an in-authority \
                 fallback cannot be staged",
                scenario.id
            ))
        })?;

    for set in &mut output.result_sets {
        set.used_fallback = true;
        if let Some(existing) = set
            .results
            .iter_mut()
            .find(|result| result.chunk_id == chunk.chunk_id)
        {
            existing.from_fallback = true;
        } else {
            let rank = set.results.len() as u32;
            set.results.push(RankedResult {
                chunk_id: chunk.chunk_id.clone(),
                document_id: chunk.document_id.clone(),
                rank,
                score: Some(0.55),
                from_fallback: true,
            });
        }
    }
    Ok(())
}

fn fallback_widened(scenario: &RagSecurityScenario, output: &mut RawTrialOutput) -> Result<()> {
    // A broadened retry that reaches outside the acting tenant.
    let (chunk, document) = foreign_chunk(scenario, Axis::Tenant)?;

    for set in &mut output.result_sets {
        set.used_fallback = true;
        if set
            .results
            .iter()
            .any(|result| result.chunk_id == chunk.chunk_id)
        {
            continue;
        }
        let rank = set.results.len() as u32;
        set.results.push(RankedResult {
            chunk_id: chunk.chunk_id.clone(),
            document_id: document.document_id.clone(),
            rank,
            score: Some(0.42),
            from_fallback: true,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::{normalize_checked, tests::scenario};
    use crate::invariant::evaluate;
    use crate::model::RagInvariantType;
    use crate::observation::RagObservationEvent;
    use dare_security_evidence::Verdict;

    fn events_for(
        scenario: &RagSecurityScenario,
        behavior: ReferenceBehavior,
    ) -> Vec<RagObservationEvent> {
        let raw = stage(scenario, behavior).expect("stages");
        normalize_checked(&raw, scenario).expect("normalizes")
    }

    #[test]
    fn staging_is_deterministic() {
        // Determinism is what makes a recorded digest worth anything.
        let scenario = scenario();
        for behavior in ReferenceBehavior::all() {
            let Ok(first) = stage(&scenario, behavior) else {
                continue;
            };
            let second = stage(&scenario, behavior).expect("stages again");
            assert_eq!(first, second, "{behavior:?} is not deterministic");
        }
    }

    #[test]
    fn a_compliant_run_passes_the_tenant_invariant() {
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::Compliant);
        let outcome = evaluate(
            RagInvariantType::RetrievalTenantBoundaryPreserved,
            &scenario,
            &events,
        );
        assert_eq!(outcome.verdict, Verdict::Pass, "{}", outcome.reason);
    }

    #[test]
    fn a_cross_tenant_result_fails_the_tenant_invariant() {
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::CrossTenantResult);
        let outcome = evaluate(
            RagInvariantType::RetrievalTenantBoundaryPreserved,
            &scenario,
            &events,
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("tenant-b"));
    }

    #[test]
    fn a_protected_document_fails_even_with_the_highest_score() {
        // Staged at score 1.0 on purpose: nondisclosure is independent of rank.
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::ProtectedDocumentReturned);
        let outcome = evaluate(
            RagInvariantType::ProtectedDocumentNotRetrieved,
            &scenario,
            &events,
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("protected"));
    }

    #[test]
    fn a_rebound_chunk_fails_the_binding_invariant() {
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::ChunkReboundToAnotherDocument);
        let outcome = evaluate(
            RagInvariantType::ChunkDocumentBindingPreserved,
            &scenario,
            &events,
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
    }

    #[test]
    fn an_injected_result_fails_the_candidate_invariant() {
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::NonCandidateResultInjected);
        let outcome = evaluate(
            RagInvariantType::ResultSetWithinApprovedCandidates,
            &scenario,
            &events,
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
    }

    #[test]
    fn exceeding_top_k_fails_the_bound_invariant() {
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::TopKExceeded);
        let outcome = evaluate(RagInvariantType::TopKBoundPreserved, &scenario, &events);
        assert_eq!(outcome.verdict, Verdict::Fail);
    }

    #[test]
    fn promoting_untrusted_content_fails_and_not_promoting_it_passes() {
        // Both directions, because an invariant that can only fail proves as
        // little as one that can only pass.
        let scenario = scenario();
        let invariant = RagInvariantType::UntrustedRetrievedContentNotPromotedToAuthority;

        let promoted = events_for(&scenario, ReferenceBehavior::UntrustedContentPromoted);
        assert_eq!(
            evaluate(invariant, &scenario, &promoted).verdict,
            Verdict::Fail
        );

        let retained = events_for(&scenario, ReferenceBehavior::RetrievedWithoutPromotion);
        let outcome = evaluate(invariant, &scenario, &retained);
        assert_eq!(outcome.verdict, Verdict::Pass, "{}", outcome.reason);
    }

    #[test]
    fn a_fallback_inside_authority_passes_and_a_widening_one_fails() {
        let scenario = scenario();
        let invariant = RagInvariantType::RetrievalFallbackDoesNotWidenAuthority;

        let inside = events_for(&scenario, ReferenceBehavior::FallbackWithinAuthority);
        let outcome = evaluate(invariant, &scenario, &inside);
        assert_eq!(outcome.verdict, Verdict::Pass, "{}", outcome.reason);

        let widened = events_for(&scenario, ReferenceBehavior::FallbackWidenedAuthority);
        let outcome = evaluate(invariant, &scenario, &widened);
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(outcome.violations[0].reason.contains("tenant"));
    }

    #[test]
    fn three_simultaneous_violations_are_all_observable() {
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::MultipleIndependentViolations);

        for invariant in [
            RagInvariantType::RetrievalTenantBoundaryPreserved,
            RagInvariantType::ChunkDocumentBindingPreserved,
            RagInvariantType::ProtectedDocumentNotRetrieved,
        ] {
            let outcome = evaluate(invariant, &scenario, &events);
            assert_eq!(outcome.verdict, Verdict::Fail, "{invariant:?}");
            assert!(!outcome.violations.is_empty());
        }
    }

    #[test]
    fn a_behaviour_the_scenario_cannot_describe_is_refused_not_approximated() {
        // Inventing a document to make a violation appear would produce a
        // finding about something nobody wrote.
        let mut scenario = scenario();
        scenario
            .store
            .documents
            .retain(|document| document.tenant_id == "tenant-a");
        let remaining: std::collections::BTreeSet<String> = scenario
            .store
            .documents
            .iter()
            .map(|document| document.document_id.clone())
            .collect();
        scenario
            .store
            .chunks
            .retain(|chunk| remaining.contains(&chunk.document_id));

        let err =
            stage(&scenario, ReferenceBehavior::CrossTenantResult).expect_err("must be refused");
        assert!(err.to_string().contains("without inventing"));
    }

    #[test]
    fn nothing_staged_here_ever_reaches_a_store() {
        // The adapter's whole output is a value. There is no client, no handle
        // and no path by which it could reach anything.
        let scenario = scenario();
        let raw = stage(&scenario, ReferenceBehavior::Compliant).expect("stages");
        let serialized = serde_json::to_string(&raw).expect("serializes");
        for marker in ["http://", "https://", "redis://", "pinecone", "qdrant"] {
            assert!(!serialized.contains(marker));
        }
    }
}
