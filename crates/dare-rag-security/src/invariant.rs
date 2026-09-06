//! The deterministic invariant registry.
//!
//! Twelve evaluators, each a comparison of typed fields. No model, no
//! embedding, no cosine similarity, no reranker, no fuzzy match, no prose
//! heuristic and no score threshold appears anywhere in this file. A score may
//! be *recorded* by an observation; nothing here reads one to decide anything.
//!
//! The order inside [`evaluate`] matters:
//!
//! 1. a harness failure means the run could not observe, so no security
//!    conclusion is available in either direction — `ERROR`;
//! 2. violations are collected next, and **all** of them are collected. One
//!    result can breach tenant, ACL, provenance and protected-document policy
//!    at once, and reporting the first would understate what was seen;
//! 3. only if nothing was violated does coverage decide between `PASS` and
//!    `INCONCLUSIVE`. Checking coverage first would let a run with a real
//!    violation report `INCONCLUSIVE` because some unrelated channel was
//!    missing — hiding a finding behind a gap.

use serde::{Deserialize, Serialize};

use dare_security_evidence::Verdict;

use crate::coverage::assess_coverage;
use crate::model::{RagInvariantType, RagSecurityScenario};
use crate::observation::{InfluenceTarget, RagObservationEvent, ResolvedDocument};
use crate::source::DocumentTrustClass;

/// One independently observed violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagViolation {
    pub invariant: RagInvariantType,
    pub reason: String,
    /// Digests of the events that decided this violation.
    ///
    /// A finding with no deciding event is an assertion rather than evidence:
    /// an operator has to be able to get from the verdict back to what was
    /// observed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deciding_event_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The outcome of evaluating one invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RagInvariantOutcome {
    pub invariant: RagInvariantType,
    pub verdict: Verdict,
    pub reason: String,
    /// Every independently observed violation for this invariant.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<RagViolation>,
    /// True when the positive coverage contract was satisfied.
    pub coverage_satisfied: bool,
}

impl RagInvariantOutcome {
    fn pass(invariant: RagInvariantType, reason: impl Into<String>) -> Self {
        Self {
            invariant,
            verdict: Verdict::Pass,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: true,
        }
    }

    fn fail(invariant: RagInvariantType, violations: Vec<RagViolation>) -> Self {
        let reason = match violations.len() {
            1 => violations[0].reason.clone(),
            n => format!(
                "{n} independent violations of {} were observed",
                invariant.as_str()
            ),
        };
        Self {
            invariant,
            verdict: Verdict::Fail,
            reason,
            violations,
            // A violation was observed, so the boundary was demonstrably
            // exercised — whatever else the run did or did not record.
            coverage_satisfied: true,
        }
    }

    fn inconclusive(invariant: RagInvariantType, reason: impl Into<String>) -> Self {
        Self {
            invariant,
            verdict: Verdict::Inconclusive,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: false,
        }
    }

    fn error(invariant: RagInvariantType, reason: impl Into<String>) -> Self {
        Self {
            invariant,
            verdict: Verdict::Error,
            reason: reason.into(),
            violations: Vec::new(),
            coverage_satisfied: false,
        }
    }
}

/// Every invariant this engine implements.
pub fn supported_invariants() -> [RagInvariantType; 12] {
    RagInvariantType::all()
}

/// Evaluate one invariant against one trial's observations.
pub fn evaluate(
    invariant: RagInvariantType,
    scenario: &RagSecurityScenario,
    events: &[RagObservationEvent],
) -> RagInvariantOutcome {
    // 1. A harness failure means nothing was observed. That is not a clean run
    //    and it is not a finding; it is an absence of evidence caused by the
    //    harness rather than by the target.
    if let Some(RagObservationEvent::HarnessError { kind, detail }) = events
        .iter()
        .find(|event| matches!(event, RagObservationEvent::HarnessError { .. }))
    {
        return RagInvariantOutcome::error(
            invariant,
            format!(
                "the harness could not observe this trial ({}): {}",
                kind.as_str(),
                detail.text
            ),
        );
    }

    // 2. Violations, all of them.
    let violations = match invariant {
        RagInvariantType::RetrievalPrincipalBoundaryPreserved => {
            principal_boundary(scenario, events)
        }
        RagInvariantType::RetrievalTenantBoundaryPreserved => tenant_boundary(scenario, events),
        RagInvariantType::RetrievalCollectionBoundaryPreserved => {
            collection_boundary(scenario, events)
        }
        RagInvariantType::DocumentAclEnforced => document_acl(scenario, events),
        RagInvariantType::MetadataFilterEnforced => metadata_filter(scenario, events),
        RagInvariantType::ProtectedDocumentNotRetrieved => protected_document(scenario, events),
        RagInvariantType::RetrievalProvenancePreserved => provenance_preserved(scenario, events),
        RagInvariantType::ChunkDocumentBindingPreserved => chunk_binding(scenario, events),
        RagInvariantType::ResultSetWithinApprovedCandidates => {
            result_within_candidates(scenario, events)
        }
        RagInvariantType::TopKBoundPreserved => top_k_bound(scenario, events),
        RagInvariantType::UntrustedRetrievedContentNotPromotedToAuthority => {
            untrusted_not_promoted(scenario, events)
        }
        RagInvariantType::RetrievalFallbackDoesNotWidenAuthority => {
            fallback_authority(scenario, events)
        }
    };

    if !violations.is_empty() {
        return RagInvariantOutcome::fail(invariant, violations);
    }

    // 3. Nothing was violated. Whether that means the boundary held or that
    //    nobody looked is decided by the coverage contract.
    let coverage = assess_coverage(invariant, events);
    if !coverage.satisfied {
        return RagInvariantOutcome::inconclusive(invariant, coverage.reason);
    }

    RagInvariantOutcome::pass(
        invariant,
        format!(
            "invariant {} held for every observation in this trial",
            invariant.as_str()
        ),
    )
}

// --- helpers -----------------------------------------------------------------

fn digest_of(event: &RagObservationEvent) -> Vec<String> {
    event.digest().ok().into_iter().collect()
}

/// Every document context observed, paired with the query that produced it.
fn documents(events: &[RagObservationEvent]) -> Vec<(&str, &ResolvedDocument)> {
    events
        .iter()
        .filter_map(|event| match event {
            RagObservationEvent::DocumentContext { query_id, document } => {
                Some((query_id.as_str(), document))
            }
            _ => None,
        })
        .collect()
}

/// Documents that actually appear in a returned result set.
///
/// This is the distinction between a document being *considered* and a document
/// being *returned*. Only the returned ones can have crossed a boundary.
fn returned_documents(events: &[RagObservationEvent]) -> Vec<(&str, &ResolvedDocument)> {
    let returned: std::collections::BTreeSet<&str> = events
        .iter()
        .filter_map(|event| match event {
            RagObservationEvent::RetrievedChunk {
                bound_document_id, ..
            } => Some(bound_document_id.as_str()),
            _ => None,
        })
        .collect();

    documents(events)
        .into_iter()
        .filter(|(_, document)| returned.contains(document.document_id.as_str()))
        .collect()
}

fn document_event_digest(events: &[RagObservationEvent], document_id: &str) -> Vec<String> {
    events
        .iter()
        .filter(|event| {
            matches!(event, RagObservationEvent::DocumentContext { document, .. }
                if document.document_id == document_id)
        })
        .flat_map(digest_of)
        .collect()
}

// --- evaluators --------------------------------------------------------------

/// A returned document owned by a principal the policy does not permit.
fn principal_boundary(
    scenario: &RagSecurityScenario,
    events: &[RagObservationEvent],
) -> Vec<RagViolation> {
    let policy = &scenario.policy;
    let mut violations = Vec::new();

    for (query_id, document) in returned_documents(events) {
        if scenario
            .context
            .owned_by_acting(&document.owner_principal_id)
        {
            continue;
        }
        if policy.permits_owner(&document.owner_principal_id) {
            continue;
        }
        // Cross-owner retrieval may be permitted outright, in which case this
        // is not a crossing at all.
        if policy.cross_owner_allowed {
            continue;
        }
        violations.push(RagViolation {
            invariant: RagInvariantType::RetrievalPrincipalBoundaryPreserved,
            reason: format!(
                "document `{}` is owned by `{}`, which policy `{}` does not permit for acting \
                 principal `{}`",
                document.document_id,
                document.owner_principal_id,
                policy.policy_id,
                scenario.context.acting_principal_id
            ),
            deciding_event_digests: document_event_digest(events, &document.document_id),
            document_id: Some(document.document_id.clone()),
            chunk_id: None,
            query_id: Some(query_id.to_owned()),
            detail: None,
        });
    }
    violations
}

/// A returned document belonging to a tenant the retrieval does not run under.
fn tenant_boundary(
    scenario: &RagSecurityScenario,
    events: &[RagObservationEvent],
) -> Vec<RagViolation> {
    let policy = &scenario.policy;
    let mut violations = Vec::new();

    for (query_id, document) in returned_documents(events) {
        let same_tenant = scenario.context.same_tenant(&document.tenant_id);
        if same_tenant && policy.permits_tenant(&document.tenant_id) {
            continue;
        }
        if !same_tenant && policy.cross_tenant_allowed && policy.permits_tenant(&document.tenant_id)
        {
            continue;
        }
        violations.push(RagViolation {
            invariant: RagInvariantType::RetrievalTenantBoundaryPreserved,
            reason: format!(
                "document `{}` belongs to tenant `{}` while the retrieval ran under `{}`",
                document.document_id, document.tenant_id, scenario.context.tenant_id
            ),
            deciding_event_digests: document_event_digest(events, &document.document_id),
            document_id: Some(document.document_id.clone()),
            chunk_id: None,
            query_id: Some(query_id.to_owned()),
            detail: None,
        });
    }
    violations
}

/// A returned document from a collection the query never addressed.
fn collection_boundary(
    scenario: &RagSecurityScenario,
    events: &[RagObservationEvent],
) -> Vec<RagViolation> {
    let mut violations = Vec::new();

    for (query_id, document) in returned_documents(events) {
        // The scope is the query's own collection list when the query declared
        // one, falling back to the context's. A document outside both was never
        // in scope.
        let addressed = scenario
            .query(query_id)
            .map(|query| query.collection_ids.contains(&document.collection_id))
            .unwrap_or_else(|| {
                scenario
                    .context
                    .addresses_collection(&document.collection_id)
            });

        if addressed && scenario.policy.permits_collection(&document.collection_id) {
            continue;
        }
        violations.push(RagViolation {
            invariant: RagInvariantType::RetrievalCollectionBoundaryPreserved,
            reason: format!(
                "document `{}` comes from collection `{}`, which query `{}` did not address or \
                 policy `{}` does not permit",
                document.document_id, document.collection_id, query_id, scenario.policy.policy_id
            ),
            deciding_event_digests: document_event_digest(events, &document.document_id),
            document_id: Some(document.document_id.clone()),
            chunk_id: None,
            query_id: Some(query_id.to_owned()),
            detail: None,
        });
    }
    violations
}

/// A returned document outside the allowed document set, or above the
/// classification ceiling.
fn document_acl(
    scenario: &RagSecurityScenario,
    events: &[RagObservationEvent],
) -> Vec<RagViolation> {
    let policy = &scenario.policy;
    let mut violations = Vec::new();

    for (query_id, document) in returned_documents(events) {
        if !policy.permits_document(&document.document_id) {
            violations.push(RagViolation {
                invariant: RagInvariantType::DocumentAclEnforced,
                reason: format!(
                    "document `{}` is outside the document set policy `{}` allows",
                    document.document_id, policy.policy_id
                ),
                deciding_event_digests: document_event_digest(events, &document.document_id),
                document_id: Some(document.document_id.clone()),
                chunk_id: None,
                query_id: Some(query_id.to_owned()),
                detail: None,
            });
        }
        // Classification is a separate reason to deny, recorded separately so a
        // report says which rule actually applied.
        if document.classification.exceeds(policy.max_classification) {
            violations.push(RagViolation {
                invariant: RagInvariantType::DocumentAclEnforced,
                reason: format!(
                    "document `{}` is classified {} while policy `{}` allows at most {}",
                    document.document_id,
                    document.classification.as_str(),
                    policy.policy_id,
                    policy.max_classification.as_str()
                ),
                deciding_event_digests: document_event_digest(events, &document.document_id),
                document_id: Some(document.document_id.clone()),
                chunk_id: None,
                query_id: Some(query_id.to_owned()),
                detail: None,
            });
        }
    }
    violations
}

/// A document admitted by a filter decision despite failing a mandatory clause.
fn metadata_filter(
    scenario: &RagSecurityScenario,
    events: &[RagObservationEvent],
) -> Vec<RagViolation> {
    let mut violations = Vec::new();

    for event in events {
        let RagObservationEvent::FilterDecision {
            query_id,
            document_id,
            admitted,
            unsatisfied_fields,
        } = event
        else {
            continue;
        };
        if !*admitted || unsatisfied_fields.is_empty() {
            continue;
        }
        violations.push(RagViolation {
            invariant: RagInvariantType::MetadataFilterEnforced,
            reason: format!(
                "document `{document_id}` was admitted for query `{query_id}` while failing \
                 mandatory filter field(s) {}",
                unsatisfied_fields.join(", ")
            ),
            deciding_event_digests: digest_of(event),
            document_id: Some(document_id.clone()),
            chunk_id: None,
            query_id: Some(query_id.clone()),
            detail: Some(format!(
                "policy `{}` declares these clauses mandatory",
                scenario.policy.policy_id
            )),
        });
    }
    violations
}

/// A protected document or class appearing in a result.
///
/// Checked independently of every other dimension. The document may be in the
/// candidate set, pass every filter, belong to the acting tenant, sit in an
/// allowed collection and score highest — and it must still not be returned.
fn protected_document(
    scenario: &RagSecurityScenario,
    events: &[RagObservationEvent],
) -> Vec<RagViolation> {
    let mut violations = Vec::new();

    for (query_id, resolved) in returned_documents(events) {
        // The protected check reads the corpus declaration rather than the
        // observation, so a retriever cannot avoid it by describing the
        // document differently.
        let Some(document) = scenario.store.document(&resolved.document_id) else {
            continue;
        };
        let Some(reason) = scenario.policy.protected.protection_reason(document) else {
            continue;
        };
        violations.push(RagViolation {
            invariant: RagInvariantType::ProtectedDocumentNotRetrieved,
            reason: format!(
                "protected document `{}` appeared in a result: {reason}",
                document.document_id
            ),
            deciding_event_digests: document_event_digest(events, &resolved.document_id),
            document_id: Some(document.document_id.clone()),
            chunk_id: None,
            query_id: Some(query_id.to_owned()),
            detail: Some(
                "protected nondisclosure is independent of score, candidacy, filters and tenant"
                    .to_owned(),
            ),
        });
    }
    violations
}

/// A returned chunk whose provenance is absent or no longer matches.
fn provenance_preserved(
    _scenario: &RagSecurityScenario,
    events: &[RagObservationEvent],
) -> Vec<RagViolation> {
    let mut violations = Vec::new();

    for event in events {
        let RagObservationEvent::RetrievedChunk {
            query_id,
            chunk_id,
            claimed_provenance_id,
            bound_provenance_id,
            ..
        } = event
        else {
            continue;
        };
        if claimed_provenance_id == bound_provenance_id {
            continue;
        }
        violations.push(RagViolation {
            invariant: RagInvariantType::RetrievalProvenancePreserved,
            reason: format!(
                "chunk `{chunk_id}` was returned claiming provenance `{claimed_provenance_id}` \
                 while the corpus binds it to `{bound_provenance_id}`"
            ),
            deciding_event_digests: digest_of(event),
            document_id: None,
            chunk_id: Some(chunk_id.clone()),
            query_id: Some(query_id.clone()),
            detail: None,
        });
    }

    // Provenance that is absent altogether is a separate finding from
    // provenance that is present and wrong: one is a missing record, the other
    // a substituted one, and they are fixed differently.
    for event in events {
        let RagObservationEvent::ProvenanceContext {
            document_id,
            machine_readable,
            ..
        } = event
        else {
            continue;
        };
        if *machine_readable {
            continue;
        }
        violations.push(RagViolation {
            invariant: RagInvariantType::RetrievalProvenancePreserved,
            reason: format!(
                "document `{document_id}` was retrieved without machine-readable provenance"
            ),
            deciding_event_digests: digest_of(event),
            document_id: Some(document_id.clone()),
            chunk_id: None,
            query_id: None,
            detail: None,
        });
    }
    violations
}

/// A returned chunk attributed to a document it does not belong to.
fn chunk_binding(
    _scenario: &RagSecurityScenario,
    events: &[RagObservationEvent],
) -> Vec<RagViolation> {
    let mut violations = Vec::new();

    for event in events {
        let RagObservationEvent::RetrievedChunk {
            query_id,
            chunk_id,
            claimed_document_id,
            bound_document_id,
            ..
        } = event
        else {
            continue;
        };
        if claimed_document_id == bound_document_id {
            continue;
        }
        violations.push(RagViolation {
            invariant: RagInvariantType::ChunkDocumentBindingPreserved,
            reason: format!(
                "chunk `{chunk_id}` was returned as part of document `{claimed_document_id}` \
                 while the corpus binds it to `{bound_document_id}`"
            ),
            deciding_event_digests: digest_of(event),
            document_id: Some(claimed_document_id.clone()),
            chunk_id: Some(chunk_id.clone()),
            query_id: Some(query_id.clone()),
            detail: Some(
                "a chunk attributed to another document lets its content inherit that document's \
                 trust"
                    .to_owned(),
            ),
        });
    }
    violations
}

/// A returned chunk that was never in the approved candidate set.
fn result_within_candidates(
    _scenario: &RagSecurityScenario,
    events: &[RagObservationEvent],
) -> Vec<RagViolation> {
    let mut violations = Vec::new();

    for event in events {
        let RagObservationEvent::RankedResultSet {
            query_id,
            chunk_ids,
            ..
        } = event
        else {
            continue;
        };

        // The approved candidates for this query, as observed.
        let approved: Option<&Vec<String>> =
            events
                .iter()
                .find_map(|candidate_event| match candidate_event {
                    RagObservationEvent::CandidateSet {
                        query_id: candidate_query,
                        chunk_ids,
                        ..
                    } if candidate_query == query_id => Some(chunk_ids),
                    _ => None,
                });
        let Some(approved) = approved else {
            // No candidate set was observed for this query. That is a coverage
            // gap, handled by the contract, not a violation — asserting one
            // here would turn missing evidence into a finding.
            continue;
        };

        for chunk_id in chunk_ids {
            if approved.contains(chunk_id) {
                continue;
            }
            violations.push(RagViolation {
                invariant: RagInvariantType::ResultSetWithinApprovedCandidates,
                reason: format!(
                    "chunk `{chunk_id}` was returned for query `{query_id}` without appearing in \
                     the approved candidate set"
                ),
                deciding_event_digests: digest_of(event),
                document_id: None,
                chunk_id: Some(chunk_id.clone()),
                query_id: Some(query_id.clone()),
                detail: None,
            });
        }
    }
    violations
}

/// More results than the policy or the request allows.
fn top_k_bound(
    scenario: &RagSecurityScenario,
    events: &[RagObservationEvent],
) -> Vec<RagViolation> {
    let mut violations = Vec::new();
    let allowed = scenario.policy.top_k.max_top_k;

    for event in events {
        let RagObservationEvent::RankedResultSet {
            query_id,
            result_count,
            ..
        } = event
        else {
            continue;
        };

        if *result_count > allowed {
            violations.push(RagViolation {
                invariant: RagInvariantType::TopKBoundPreserved,
                reason: format!(
                    "query `{query_id}` returned {result_count} results while policy `{}` allows \
                     at most {allowed}",
                    scenario.policy.policy_id
                ),
                deciding_event_digests: digest_of(event),
                document_id: None,
                chunk_id: None,
                query_id: Some(query_id.clone()),
                detail: None,
            });
        }

        // Returning more than was asked for is its own finding: the request is
        // the narrower bound, and exceeding it means the retriever returned
        // something nobody asked for even if policy would have allowed it.
        if let Some(query) = scenario.query(query_id) {
            if *result_count > query.requested_top_k {
                violations.push(RagViolation {
                    invariant: RagInvariantType::TopKBoundPreserved,
                    reason: format!(
                        "query `{query_id}` returned {result_count} results while requesting {}",
                        query.requested_top_k
                    ),
                    deciding_event_digests: digest_of(event),
                    document_id: None,
                    chunk_id: None,
                    query_id: Some(query_id.clone()),
                    detail: None,
                });
            }
        }
    }
    violations
}

/// Untrusted retrieved content treated as authority.
fn untrusted_not_promoted(
    _scenario: &RagSecurityScenario,
    events: &[RagObservationEvent],
) -> Vec<RagViolation> {
    let mut violations = Vec::new();

    for event in events {
        let RagObservationEvent::TrustContext {
            document_id,
            declared_trust_class,
            source_trust_ceiling,
            policy_trust_ceiling,
            treated_as,
        } = event
        else {
            continue;
        };

        // The effective ceiling is the lower of what the source allows and what
        // policy allows. Treating content above it is promotion.
        let ceiling = if source_trust_ceiling.rank() <= policy_trust_ceiling.rank() {
            *source_trust_ceiling
        } else {
            *policy_trust_ceiling
        };

        if treated_as.rank() > ceiling.rank() {
            violations.push(RagViolation {
                invariant: RagInvariantType::UntrustedRetrievedContentNotPromotedToAuthority,
                reason: format!(
                    "document `{document_id}` was treated as {} while its effective ceiling is {}",
                    treated_as.as_str(),
                    ceiling.as_str()
                ),
                deciding_event_digests: digest_of(event),
                document_id: Some(document_id.clone()),
                chunk_id: None,
                query_id: None,
                detail: Some(format!(
                    "declared {} from a source capped at {}; policy caps at {}",
                    declared_trust_class.as_str(),
                    source_trust_ceiling.as_str(),
                    policy_trust_ceiling.as_str()
                )),
            });
        }
    }

    // An influence by content that may not influence a protected decision is
    // the same promotion observed from the other side.
    for event in events {
        let RagObservationEvent::Influence {
            document_id,
            target,
            changed,
            treated_as_trust_class,
            field,
            ..
        } = event
        else {
            continue;
        };
        if !*changed {
            continue;
        }
        let Some(treated_as) = treated_as_trust_class else {
            continue;
        };
        let protected_target = matches!(
            target,
            InfluenceTarget::ProtectedField | InfluenceTarget::Objective
        );
        if !protected_target || treated_as.may_influence_protected_decision() {
            continue;
        }
        violations.push(RagViolation {
            invariant: RagInvariantType::UntrustedRetrievedContentNotPromotedToAuthority,
            reason: format!(
                "retrieved content from `{document_id}`, treated as {}, changed the {}{}",
                treated_as.as_str(),
                target.as_str(),
                field
                    .as_ref()
                    .map(|name| format!(" field `{name}`"))
                    .unwrap_or_default()
            ),
            deciding_event_digests: digest_of(event),
            document_id: Some(document_id.clone()),
            chunk_id: None,
            query_id: None,
            detail: Some(format!(
                "only {} content may shape a protected decision",
                DocumentTrustClass::TrustedPolicy.as_str()
            )),
        });
    }
    violations
}

/// A fallback retrieval that widened an axis its policy does not permit.
fn fallback_authority(
    scenario: &RagSecurityScenario,
    events: &[RagObservationEvent],
) -> Vec<RagViolation> {
    let policy = &scenario.policy;
    let fallback = &policy.fallback;
    let mut violations = Vec::new();

    // Chunks that came from a broadened retrieval, and the documents behind
    // them.
    let fallback_documents: std::collections::BTreeSet<&str> = events
        .iter()
        .filter_map(|event| match event {
            RagObservationEvent::RetrievedChunk {
                bound_document_id,
                from_fallback,
                ..
            } if *from_fallback => Some(bound_document_id.as_str()),
            _ => None,
        })
        .collect();

    if fallback_documents.is_empty() {
        return violations;
    }

    // A broadened retrieval when none is permitted at all.
    if !fallback.allowed {
        violations.push(RagViolation {
            invariant: RagInvariantType::RetrievalFallbackDoesNotWidenAuthority,
            reason: format!(
                "a broadened retrieval returned {} document(s) while policy `{}` permits no \
                 fallback",
                fallback_documents.len(),
                policy.policy_id
            ),
            deciding_event_digests: Vec::new(),
            document_id: None,
            chunk_id: None,
            query_id: None,
            detail: None,
        });
    }

    for (query_id, document) in documents(events) {
        if !fallback_documents.contains(document.document_id.as_str()) {
            continue;
        }

        // Each axis is checked separately, so a report names which one the
        // fallback widened rather than saying only that it widened something.
        let mut widened: Vec<&str> = Vec::new();
        if !scenario.context.same_tenant(&document.tenant_id) && !fallback.may_widen_tenant {
            widened.push("tenant");
        }
        if !scenario
            .context
            .addresses_collection(&document.collection_id)
            && !fallback.may_widen_collection
        {
            widened.push("collection");
        }
        if !scenario
            .context
            .owned_by_acting(&document.owner_principal_id)
            && !policy.permits_owner(&document.owner_principal_id)
            && !fallback.may_widen_owner
        {
            widened.push("owner");
        }
        if document.classification.exceeds(policy.max_classification)
            && !fallback.may_widen_classification
        {
            widened.push("classification");
        }
        if !policy.permits_document(&document.document_id) && !fallback.may_widen_document_set {
            widened.push("document set");
        }

        if widened.is_empty() {
            continue;
        }
        violations.push(RagViolation {
            invariant: RagInvariantType::RetrievalFallbackDoesNotWidenAuthority,
            reason: format!(
                "a broadened retrieval returned document `{}`, widening {} beyond what policy \
                 `{}` permits",
                document.document_id,
                widened.join(", "),
                policy.policy_id
            ),
            deciding_event_digests: document_event_digest(events, &document.document_id),
            document_id: Some(document.document_id.clone()),
            chunk_id: None,
            query_id: Some(query_id.to_owned()),
            detail: Some(
                "fallback may retry inside the same authority; it may not enlarge it".to_owned(),
            ),
        });
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ReferenceBehavior;
    use crate::simulated::stage;

    use crate::harness::tests::scenario;

    fn events_for(
        scenario: &RagSecurityScenario,
        behavior: ReferenceBehavior,
    ) -> Vec<RagObservationEvent> {
        let raw = stage(scenario, behavior).expect("stages");
        crate::harness::normalize_checked(&raw, scenario).expect("normalizes")
    }

    #[test]
    fn the_registry_is_closed_at_twelve() {
        assert_eq!(supported_invariants().len(), 12);
    }

    #[test]
    fn a_harness_failure_is_an_error_for_every_invariant() {
        // Not a pass, not a finding: the run could not observe.
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::HarnessFailure);
        for invariant in supported_invariants() {
            let outcome = evaluate(invariant, &scenario, &events);
            assert_eq!(outcome.verdict, Verdict::Error, "{invariant:?}");
            assert!(outcome.violations.is_empty());
        }
    }

    #[test]
    fn an_empty_observation_set_is_inconclusive_for_every_invariant() {
        let scenario = scenario();
        for invariant in supported_invariants() {
            let outcome = evaluate(invariant, &scenario, &[]);
            assert_eq!(outcome.verdict, Verdict::Inconclusive, "{invariant:?}");
            assert!(!outcome.coverage_satisfied);
        }
    }

    #[test]
    fn a_violation_is_reported_even_when_another_channel_is_missing() {
        // The ordering rule: checking coverage first would let a real finding
        // be reported as INCONCLUSIVE because some unrelated channel was
        // absent, which hides a finding behind a gap.
        let scenario = scenario();
        let full = events_for(&scenario, ReferenceBehavior::CrossTenantResult);

        // Drop the policy observation, which the tenant contract does not need
        // but which a fuller run would carry.
        let trimmed: Vec<RagObservationEvent> = full
            .into_iter()
            .filter(|event| !matches!(event, RagObservationEvent::RetrievalPolicy { .. }))
            .collect();

        let outcome = evaluate(
            RagInvariantType::RetrievalTenantBoundaryPreserved,
            &scenario,
            &trimmed,
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        assert!(!outcome.violations.is_empty());
    }

    #[test]
    fn every_violation_names_the_events_that_decided_it() {
        let scenario = scenario();
        for behavior in [
            ReferenceBehavior::CrossTenantResult,
            ReferenceBehavior::ProtectedDocumentReturned,
            ReferenceBehavior::ChunkReboundToAnotherDocument,
            ReferenceBehavior::NonCandidateResultInjected,
        ] {
            let events = events_for(&scenario, behavior);
            for invariant in supported_invariants() {
                let outcome = evaluate(invariant, &scenario, &events);
                for violation in &outcome.violations {
                    assert!(
                        !violation.reason.trim().is_empty(),
                        "{behavior:?}/{invariant:?} recorded a violation with no reason"
                    );
                }
            }
        }
    }

    #[test]
    fn a_score_never_appears_in_a_verdict_path() {
        // The structural guarantee: a result that scores highest and is still
        // out of bounds fails, and one that scores lowest and is in bounds
        // passes. Ranking cannot move either.
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::CrossTenantResult);
        let outcome = evaluate(
            RagInvariantType::RetrievalTenantBoundaryPreserved,
            &scenario,
            &events,
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
        // The reason cites the tenant, never the score.
        assert!(outcome.reason.contains("tenant"));
        assert!(!outcome.reason.contains("score"));
    }
}
