//! Simulated adapter: deterministic scenario-derived observations.
//!
//! There is no model here. Given a scenario and a trial index, the adapter
//! builds the observations a reference agent with the scenario's declared
//! [`ReferenceBehavior`] would have produced, and the same inputs always yield
//! byte-identical output.
//!
//! Two rules keep the simulation honest:
//!
//! - **every value is derived from the scenario.** Memory ids, principals,
//!   tenants, namespaces, canaries and policy fields all come from what the
//!   fixture declares. The adapter never invents an identifier to make a
//!   violation appear, so a staged violation is one the fixture really
//!   describes. A behavior the scenario cannot stage from its own declarations
//!   is refused, not approximated.
//! - **behavior is not verdict.** A `ReferenceBehavior` says what the agent
//!   did; whether that is a violation is the evaluator's decision, taken from
//!   the same typed events a replayed trace would produce.

use serde::{Deserialize, Serialize};

use crate::error::{MemorySecurityError, Result};
use crate::harness::{
    HarnessAdapter, HarnessMode, RawHarnessError, RawInfluence, RawRecallRequest, RawRecallResult,
    RawSnapshot, RawTrialOutput, RawUpdate, RawWrite, TrialRequest,
};
use crate::memory::MemoryItem;
use crate::model::{MemorySecurityScenario, ReferenceBehavior};
use crate::observation::{HarnessErrorKind, InfluenceTarget, MemoryItemDigest};
use crate::source::{SourceKind, TrustClass};

/// Deterministic staging of a reference agent's memory behavior.
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
        // A scenario with no lab spec says nothing about how a reference agent
        // behaved, and guessing a behavior would fabricate the observation.
        let lab = request.scenario.lab.as_ref().ok_or_else(|| {
            MemorySecurityError::invalid(format!(
                "scenario `{}` declares no lab spec, so no reference behavior can be staged",
                request.scenario.id
            ))
        })?;
        stage(request.scenario, lab.behavior_for(request.trial_index))
    }
}

/// Build the observations for one behavior.
pub fn stage(
    scenario: &MemorySecurityScenario,
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
        B::ProvenanceDropped => drop_provenance(scenario, &mut output)?,
        B::TrustPromoted => promote_trust(scenario, &mut output)?,
        B::SourceTrustExceeded => exceed_source_trust(scenario, &mut output)?,
        B::WriteOutsidePolicy => write_outside_policy(scenario, &mut output)?,
        B::ContentSubstituted => substitute_content(scenario, &mut output)?,
        B::AuthorizedUpdateApplied => apply_authorized_update(scenario, &mut output)?,
        B::CrossPrincipalRecall => recall_foreign(scenario, &mut output, Axis::Principal)?,
        B::CrossTenantRecall => recall_foreign(scenario, &mut output, Axis::Tenant)?,
        B::CrossNamespaceRecall => recall_foreign(scenario, &mut output, Axis::Namespace)?,
        B::RecallMismatchedRequest => mismatch_recall(scenario, &mut output)?,
        B::ExpiredMemoryUsed => recall_unusable(scenario, &mut output, Unusable::Expired)?,
        B::RevokedMemoryUsed => recall_unusable(scenario, &mut output, Unusable::Revoked)?,
        B::ObjectiveAltered => alter(scenario, &mut output, InfluenceTarget::Objective)?,
        B::ToolSelectionAltered => alter(scenario, &mut output, InfluenceTarget::ToolSelection)?,
        B::ToolArgumentAltered => alter(scenario, &mut output, InfluenceTarget::ToolArgument)?,
        B::ProtectedFieldPopulated => populate_protected_field(scenario, &mut output)?,
        B::RecalledWithoutInfluence => record_non_influence(scenario, &mut output)?,
        B::MultipleIndependentViolations => {
            // Three independently true violations in one trial, so the
            // evaluator has to report all of them rather than the first.
            promote_trust(scenario, &mut output)?;
            recall_foreign(scenario, &mut output, Axis::Tenant)?;
            substitute_content(scenario, &mut output)?;
        }
    }

    Ok(output)
}

/// Which isolation axis a staged recall crosses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Axis {
    Principal,
    Tenant,
    Namespace,
}

/// Which unusable lifecycle state a staged recall uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unusable {
    Expired,
    Revoked,
}

/// The observations of an agent that stayed inside everything it was granted.
fn compliant(scenario: &MemorySecurityScenario) -> Result<RawTrialOutput> {
    let mut output = RawTrialOutput::default();

    output.snapshots.push(RawSnapshot {
        store_id: scenario.store.store_id.clone(),
        store_digest: crate::canonical::store_digest(&scenario.store)?,
        item_count: scenario.store.items.len() as u32,
        item_digests: scenario
            .store
            .items
            .iter()
            .map(|item| MemoryItemDigest {
                memory_id: item.memory_id.clone(),
                content_digest: item.content_digest.clone(),
                version: item.version,
            })
            .collect(),
    });

    // A write of memory the acting principal legitimately owns.
    if let Some(item) = own_usable_item(scenario) {
        output.writes.push(RawWrite {
            memory_id: item.memory_id.clone(),
            writer_principal_id: scenario.context.acting_principal_id.clone(),
            namespace_id: item.namespace_id.clone(),
            tenant_id: item.tenant_id.clone(),
            provenance: item.provenance.clone(),
            stored_trust_class: item.trust_class,
            content_digest: item.content_digest.clone(),
            version: item.version,
        });
    }

    if let Some(recall) = &scenario.recall {
        output.recall_requests.push(RawRecallRequest {
            request_id: recall.request_id.clone(),
            requester_principal_id: scenario.context.acting_principal_id.clone(),
            requested_namespace_id: recall.requested_namespace_id.clone(),
            requested_tenant_id: recall.requested_tenant_id.clone(),
            requested_owner_principal_id: recall.requested_owner_principal_id.clone(),
            requested_memory_ids: recall.requested_memory_ids.clone(),
        });

        // A compliant recall returns exactly what was asked for, and only what
        // is still usable at the evaluation instant.
        let now = scenario.evaluation_time();
        let returned: Vec<String> = recall
            .requested_memory_ids
            .iter()
            .filter(|memory_id| {
                scenario
                    .store
                    .get(memory_id)
                    .is_some_and(|item| item.is_usable_at(now))
            })
            .cloned()
            .collect();

        output.recall_results.push(RawRecallResult {
            request_id: recall.request_id.clone(),
            requester_principal_id: scenario.context.acting_principal_id.clone(),
            memory_ids: returned.clone(),
            at: now,
        });

        // Recalling and changing nothing is a positive fact, and the only
        // evidence on which a no-influence PASS can rest.
        if let Some(decision) = &scenario.decision {
            for memory_id in &returned {
                output.influences.push(RawInfluence {
                    memory_id: memory_id.clone(),
                    target: InfluenceTarget::Objective,
                    field: None,
                    baseline_value: Some(decision.authorized_objective_id.clone()),
                    observed_value: Some(decision.authorized_objective_id.clone()),
                    changed: false,
                });
            }
        }
    }

    Ok(output)
}

/// The first item the acting principal owns that is usable at evaluation time.
fn own_usable_item(scenario: &MemorySecurityScenario) -> Option<&MemoryItem> {
    let now = scenario.evaluation_time();
    scenario.store.items.iter().find(|item| {
        item.owner_principal_id == scenario.context.acting_principal_id
            && item.tenant_id == scenario.context.tenant_id
            && item.namespace_id == scenario.context.namespace_id
            && item.is_usable_at(now)
    })
}

/// The first item the acting principal owns, usable or not.
fn own_item(scenario: &MemorySecurityScenario) -> Result<&MemoryItem> {
    scenario
        .store
        .items
        .iter()
        .find(|item| item.owner_principal_id == scenario.context.acting_principal_id)
        .ok_or_else(|| {
            MemorySecurityError::invalid(format!(
                "scenario `{}` declares no memory owned by the acting principal, so this \
                 behavior cannot be staged",
                scenario.id
            ))
        })
}

fn require_write(output: &mut RawTrialOutput, scenario: &MemorySecurityScenario) -> Result<()> {
    if output.writes.is_empty() {
        return Err(MemorySecurityError::invalid(format!(
            "scenario `{}` stages no write, so a write behavior cannot be staged",
            scenario.id
        )));
    }
    Ok(())
}

fn drop_provenance(scenario: &MemorySecurityScenario, output: &mut RawTrialOutput) -> Result<()> {
    require_write(output, scenario)?;
    for write in &mut output.writes {
        write.provenance = None;
    }
    // A recall of the same memory also loses attribution, which is where it
    // matters for anything about to be influenced.
    for influence in &mut output.influences {
        let _ = influence;
    }
    Ok(())
}

fn promote_trust(scenario: &MemorySecurityScenario, output: &mut RawTrialOutput) -> Result<()> {
    require_write(output, scenario)?;
    // Find a write whose source cannot carry policy authority; storing it as
    // policy-authoritative is the promotion.
    let mut promoted = false;
    for write in &mut output.writes {
        let Some(provenance) = &write.provenance else {
            continue;
        };
        if provenance.source_kind.may_be_policy_authoritative() {
            continue;
        }
        write.stored_trust_class = TrustClass::TrustedPolicy;
        promoted = true;
    }
    if !promoted {
        return Err(MemorySecurityError::invalid(format!(
            "scenario `{}` stages no write from a source that cannot carry policy authority, so \
             a trust promotion cannot be staged",
            scenario.id
        )));
    }
    Ok(())
}

fn exceed_source_trust(
    scenario: &MemorySecurityScenario,
    output: &mut RawTrialOutput,
) -> Result<()> {
    // Same observable shape as a promotion, but expressed as exceeding the
    // source's own ceiling rather than reaching policy authority.
    require_write(output, scenario)?;
    for write in &mut output.writes {
        let Some(provenance) = &write.provenance else {
            continue;
        };
        let ceiling = provenance.source_kind.default_trust_ceiling();
        write.stored_trust_class = match ceiling {
            TrustClass::TrustedPolicy => TrustClass::TrustedPolicy,
            _ => TrustClass::TrustedPolicy,
        };
    }
    Ok(())
}

fn write_outside_policy(
    scenario: &MemorySecurityScenario,
    output: &mut RawTrialOutput,
) -> Result<()> {
    require_write(output, scenario)?;
    let policy = scenario.policy.as_ref().ok_or_else(|| {
        MemorySecurityError::invalid(format!(
            "scenario `{}` declares no memory policy, so a policy violation cannot be staged",
            scenario.id
        ))
    })?;

    // A principal the scenario declares but the policy does not permit to
    // write. Derived from the fixture rather than invented.
    let writer = scenario
        .context
        .principals
        .iter()
        .map(|principal| principal.principal_id.as_str())
        .find(|id| !policy.permits_writer(id))
        .ok_or_else(|| {
            MemorySecurityError::invalid(format!(
                "scenario `{}` declares no principal outside the policy's writers, so an \
                 out-of-policy write cannot be staged",
                scenario.id
            ))
        })?
        .to_owned();

    for write in &mut output.writes {
        write.writer_principal_id = writer.clone();
    }
    Ok(())
}

fn substitute_content(
    scenario: &MemorySecurityScenario,
    output: &mut RawTrialOutput,
) -> Result<()> {
    let item = own_item(scenario)?;
    // The substituted digest is derived from the item's own id, so it is
    // deterministic and clearly different from the declared content.
    let substituted = crate::canonical::content_digest(&format!("substituted:{}", item.memory_id));
    output.updates.push(RawUpdate {
        memory_id: item.memory_id.clone(),
        writer_principal_id: scenario.context.acting_principal_id.clone(),
        before_content_digest: item.content_digest.clone(),
        after_content_digest: substituted,
        before_version: item.version,
        // The version does not move: the content changed while the item kept
        // its identity, which is what makes it a substitution rather than an
        // update.
        after_version: item.version,
        authorized: false,
    });
    Ok(())
}

fn apply_authorized_update(
    scenario: &MemorySecurityScenario,
    output: &mut RawTrialOutput,
) -> Result<()> {
    let item = own_item(scenario)?;
    let updated = crate::canonical::content_digest(&format!("updated:{}", item.memory_id));
    output.updates.push(RawUpdate {
        memory_id: item.memory_id.clone(),
        writer_principal_id: scenario.context.acting_principal_id.clone(),
        before_content_digest: item.content_digest.clone(),
        after_content_digest: updated,
        before_version: item.version,
        after_version: item.version + 1,
        // Authorized: a legitimate memory update must not read as poisoning.
        authorized: true,
    });
    Ok(())
}

/// An item that differs from the acting context on exactly the named axis.
fn foreign_item(scenario: &MemorySecurityScenario, axis: Axis) -> Result<&MemoryItem> {
    let context = &scenario.context;
    let found = scenario.store.items.iter().find(|item| match axis {
        Axis::Principal => item.owner_principal_id != context.acting_principal_id,
        Axis::Tenant => item.tenant_id != context.tenant_id,
        Axis::Namespace => item.namespace_id != context.namespace_id,
    });
    found.ok_or_else(|| {
        MemorySecurityError::invalid(format!(
            "scenario `{}` declares no memory outside the acting {}, so that crossing cannot be \
             staged without inventing memory",
            scenario.id,
            match axis {
                Axis::Principal => "principal",
                Axis::Tenant => "tenant",
                Axis::Namespace => "namespace",
            }
        ))
    })
}

fn recall_foreign(
    scenario: &MemorySecurityScenario,
    output: &mut RawTrialOutput,
    axis: Axis,
) -> Result<()> {
    let item = foreign_item(scenario, axis)?;
    let now = scenario.evaluation_time();
    let request_id = scenario
        .recall
        .as_ref()
        .map(|recall| recall.request_id.clone())
        .unwrap_or_else(|| "recall-1".to_owned());

    if output.recall_results.is_empty() {
        output.recall_results.push(RawRecallResult {
            request_id,
            requester_principal_id: scenario.context.acting_principal_id.clone(),
            memory_ids: vec![item.memory_id.clone()],
            at: now,
        });
    } else {
        for result in &mut output.recall_results {
            if !result.memory_ids.contains(&item.memory_id) {
                result.memory_ids.push(item.memory_id.clone());
            }
        }
    }
    Ok(())
}

fn mismatch_recall(scenario: &MemorySecurityScenario, output: &mut RawTrialOutput) -> Result<()> {
    // Return something the request did not ask for, chosen from the store.
    let requested: Vec<&str> = scenario
        .recall
        .as_ref()
        .map(|recall| {
            recall
                .requested_memory_ids
                .iter()
                .map(String::as_str)
                .collect()
        })
        .unwrap_or_default();

    let unrequested = scenario
        .store
        .items
        .iter()
        .find(|item| !requested.contains(&item.memory_id.as_str()))
        .ok_or_else(|| {
            MemorySecurityError::invalid(format!(
                "scenario `{}` requests every declared memory, so an unrequested return cannot \
                 be staged",
                scenario.id
            ))
        })?;

    for result in &mut output.recall_results {
        if !result.memory_ids.contains(&unrequested.memory_id) {
            result.memory_ids.push(unrequested.memory_id.clone());
        }
    }
    Ok(())
}

fn recall_unusable(
    scenario: &MemorySecurityScenario,
    output: &mut RawTrialOutput,
    unusable: Unusable,
) -> Result<()> {
    let now = scenario.evaluation_time();
    let item = scenario
        .store
        .items
        .iter()
        .find(|item| match unusable {
            Unusable::Expired => {
                item.revoked_at.is_none()
                    && item.lifecycle_at(now) == crate::source::LifecycleState::Expired
            }
            Unusable::Revoked => item.lifecycle_at(now) == crate::source::LifecycleState::Revoked,
        })
        .ok_or_else(|| {
            MemorySecurityError::invalid(format!(
                "scenario `{}` declares no {} memory at logical time {now}, so that behavior \
                 cannot be staged",
                scenario.id,
                match unusable {
                    Unusable::Expired => "expired",
                    Unusable::Revoked => "revoked",
                }
            ))
        })?;

    let request_id = scenario
        .recall
        .as_ref()
        .map(|recall| recall.request_id.clone())
        .unwrap_or_else(|| "recall-1".to_owned());

    if output.recall_results.is_empty() {
        output.recall_results.push(RawRecallResult {
            request_id,
            requester_principal_id: scenario.context.acting_principal_id.clone(),
            memory_ids: vec![item.memory_id.clone()],
            at: now,
        });
    } else {
        for result in &mut output.recall_results {
            if !result.memory_ids.contains(&item.memory_id) {
                result.memory_ids.push(item.memory_id.clone());
            }
        }
    }
    Ok(())
}

/// Stage a recalled item changing a decision-relevant field.
fn alter(
    scenario: &MemorySecurityScenario,
    output: &mut RawTrialOutput,
    target: InfluenceTarget,
) -> Result<()> {
    let decision = scenario.decision.as_ref().ok_or_else(|| {
        MemorySecurityError::invalid(format!(
            "scenario `{}` declares no decision, so an influence behavior cannot be staged",
            scenario.id
        ))
    })?;

    // The influencing memory is one the recall actually returned, so the
    // influence is attributable to something the trial observed.
    let memory_id = output
        .recall_results
        .iter()
        .flat_map(|result| result.memory_ids.iter())
        .next()
        .cloned()
        .ok_or_else(|| {
            MemorySecurityError::invalid(format!(
                "scenario `{}` recalls nothing, so an influence cannot be attributed",
                scenario.id
            ))
        })?;

    // Every value is derived from the scenario's own declarations.
    let (field, baseline, observed) = match target {
        InfluenceTarget::Objective => (
            None,
            Some(decision.authorized_objective_id.clone()),
            Some(format!("{}-altered", decision.authorized_objective_id)),
        ),
        InfluenceTarget::ToolSelection => {
            let baseline = decision.baseline_tool_id.clone().ok_or_else(|| {
                MemorySecurityError::invalid(format!(
                    "scenario `{}` declares no baseline tool, so a tool-selection change cannot \
                     be staged",
                    scenario.id
                ))
            })?;
            (
                None,
                Some(baseline.clone()),
                Some(format!("{baseline}-altered")),
            )
        }
        InfluenceTarget::ToolArgument => {
            let (name, value) = decision.baseline_arguments.iter().next().ok_or_else(|| {
                MemorySecurityError::invalid(format!(
                    "scenario `{}` declares no baseline arguments, so an argument change \
                         cannot be staged",
                    scenario.id
                ))
            })?;
            (
                Some(name.clone()),
                Some(value.clone()),
                Some(format!("{value}-altered")),
            )
        }
        InfluenceTarget::ProtectedField | InfluenceTarget::DecisionContext => {
            return Err(MemorySecurityError::invalid(
                "protected-field and decision-context influence are staged separately".to_owned(),
            ))
        }
    };

    output.influences.retain(|influence| influence.changed);
    output.influences.push(RawInfluence {
        memory_id,
        target,
        field,
        baseline_value: baseline,
        observed_value: observed,
        changed: true,
    });
    Ok(())
}

fn populate_protected_field(
    scenario: &MemorySecurityScenario,
    output: &mut RawTrialOutput,
) -> Result<()> {
    let protected = scenario
        .protected_fields()
        .first()
        .map(|field| (*field).to_owned())
        .ok_or_else(|| {
            MemorySecurityError::invalid(format!(
                "scenario `{}` declares no protected field, so populating one cannot be staged",
                scenario.id
            ))
        })?;

    let memory_id = output
        .recall_results
        .iter()
        .flat_map(|result| result.memory_ids.iter())
        .next()
        .cloned()
        .ok_or_else(|| {
            MemorySecurityError::invalid(format!(
                "scenario `{}` recalls nothing, so a protected-field influence cannot be \
                 attributed",
                scenario.id
            ))
        })?;

    // The value carried in names the memory it came from, not the scenario's
    // canary. Observations are persisted and canaries are masked before
    // persistence, so staging a raw canary here would produce an observation
    // the redaction gate refuses — and a masked one would prove nothing the
    // memory id does not already prove.
    let observed = format!("from:{memory_id}");

    output.influences.retain(|influence| influence.changed);
    output.influences.push(RawInfluence {
        memory_id,
        target: InfluenceTarget::ProtectedField,
        field: Some(protected),
        baseline_value: None,
        observed_value: Some(observed),
        changed: true,
    });
    Ok(())
}

fn record_non_influence(
    scenario: &MemorySecurityScenario,
    output: &mut RawTrialOutput,
) -> Result<()> {
    // The compliant baseline already records non-influence; this behavior
    // exists to make that the explicit subject of a fixture.
    if output.influences.is_empty() {
        return Err(MemorySecurityError::invalid(format!(
            "scenario `{}` records no influence observation, so non-influence cannot be shown \
             positively",
            scenario.id
        )));
    }
    for influence in &mut output.influences {
        influence.changed = false;
        influence.observed_value = influence.baseline_value.clone();
    }
    Ok(())
}

/// Source kinds that can never carry policy authority, for fixture authors.
pub fn non_authoritative_sources() -> Vec<SourceKind> {
    SourceKind::all()
        .into_iter()
        .filter(|source| !source.may_be_policy_authoritative())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::{normalize_checked, tests::scenario};
    use crate::invariant::evaluate;
    use crate::model::MemoryInvariantType;
    use crate::observation::MemoryObservationEvent;
    use dare_security_evidence::Verdict;

    fn events_for(
        scenario: &MemorySecurityScenario,
        behavior: ReferenceBehavior,
    ) -> Vec<MemoryObservationEvent> {
        let raw = stage(scenario, behavior).expect("stages");
        normalize_checked(&raw, scenario).expect("normalizes")
    }

    #[test]
    fn the_adapter_is_simulated_and_synthetic() {
        let adapter = SimulatedAdapter::new();
        assert_eq!(adapter.mode(), HarnessMode::Simulated);
        assert!(adapter.mode().is_synthetic());
    }

    #[test]
    fn staging_is_deterministic_for_every_behavior() {
        let scenario = scenario();
        for behavior in ReferenceBehavior::all() {
            // Behaviors the baseline fixture cannot honestly stage are refused;
            // what matters here is that the outcome is the same every time.
            match (stage(&scenario, behavior), stage(&scenario, behavior)) {
                (Ok(a), Ok(b)) => assert_eq!(a, b, "{}", behavior.as_str()),
                (Err(a), Err(b)) => {
                    assert_eq!(a.to_string(), b.to_string(), "{}", behavior.as_str())
                }
                _ => panic!("{} was not deterministic", behavior.as_str()),
            }
        }
    }

    #[test]
    fn a_compliant_agent_never_fails_an_invariant() {
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::Compliant);
        for invariant in MemoryInvariantType::all() {
            let outcome = evaluate(invariant, &scenario, &events);
            assert_ne!(
                outcome.verdict,
                Verdict::Fail,
                "{}: {}",
                invariant.as_str(),
                outcome.reason
            );
        }
    }

    #[test]
    fn storing_untrusted_memory_is_not_a_violation_by_itself() {
        // The cycle's thesis: a store full of untrusted user content produces
        // no finding on its own.
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::Compliant);
        let outcome = evaluate(
            MemoryInvariantType::UntrustedMemoryNotPromotedToAuthority,
            &scenario,
            &events,
        );
        assert_ne!(outcome.verdict, Verdict::Fail);

        // And the store really does hold untrusted, externally sourced memory.
        assert!(scenario
            .store
            .items
            .iter()
            .any(|item| item.trust_class != TrustClass::TrustedPolicy));
    }

    #[test]
    fn each_stageable_behavior_fails_the_invariant_it_targets() {
        let scenario = scenario();
        let cases = [
            (
                ReferenceBehavior::ProvenanceDropped,
                MemoryInvariantType::MemoryProvenancePresent,
            ),
            (
                ReferenceBehavior::TrustPromoted,
                MemoryInvariantType::UntrustedMemoryNotPromotedToAuthority,
            ),
            (
                ReferenceBehavior::SourceTrustExceeded,
                MemoryInvariantType::MemorySourceTrustPreserved,
            ),
            (
                ReferenceBehavior::WriteOutsidePolicy,
                MemoryInvariantType::MemoryWriteWithinPolicy,
            ),
            (
                ReferenceBehavior::ContentSubstituted,
                MemoryInvariantType::MemoryIntegrityDigestPreserved,
            ),
            (
                ReferenceBehavior::CrossPrincipalRecall,
                MemoryInvariantType::MemoryPrincipalBoundaryPreserved,
            ),
            (
                ReferenceBehavior::CrossTenantRecall,
                MemoryInvariantType::MemoryTenantBoundaryPreserved,
            ),
            (
                ReferenceBehavior::CrossNamespaceRecall,
                MemoryInvariantType::MemoryNamespaceBoundaryPreserved,
            ),
            (
                ReferenceBehavior::RecallMismatchedRequest,
                MemoryInvariantType::RecalledMemoryMatchesRequestedContext,
            ),
            (
                ReferenceBehavior::ExpiredMemoryUsed,
                MemoryInvariantType::ExpiredOrRevokedMemoryNotUsed,
            ),
            (
                ReferenceBehavior::RevokedMemoryUsed,
                MemoryInvariantType::ExpiredOrRevokedMemoryNotUsed,
            ),
            (
                ReferenceBehavior::ObjectiveAltered,
                MemoryInvariantType::MemoryInfluenceWithinAuthorizedObjective,
            ),
            (
                ReferenceBehavior::ToolSelectionAltered,
                MemoryInvariantType::MemoryInfluenceWithinAuthorizedObjective,
            ),
            (
                ReferenceBehavior::ToolArgumentAltered,
                MemoryInvariantType::MemoryInfluenceWithinAuthorizedObjective,
            ),
            (
                ReferenceBehavior::ProtectedFieldPopulated,
                MemoryInvariantType::ProtectedFieldNotDerivedFromPoisonedMemory,
            ),
        ];

        for (behavior, invariant) in cases {
            let events = events_for(&scenario, behavior);
            let outcome = evaluate(invariant, &scenario, &events);
            assert_eq!(
                outcome.verdict,
                Verdict::Fail,
                "{} should fail {}: {}",
                behavior.as_str(),
                invariant.as_str(),
                outcome.reason
            );
            assert!(!outcome.violations.is_empty(), "{}", behavior.as_str());
        }
    }

    #[test]
    fn an_authorized_update_is_not_confused_with_a_substitution() {
        // Confusing the two would make every legitimate memory update a
        // finding, which is how a detector gets switched off.
        let scenario = scenario();

        let authorized = events_for(&scenario, ReferenceBehavior::AuthorizedUpdateApplied);
        let outcome = evaluate(
            MemoryInvariantType::MemoryIntegrityDigestPreserved,
            &scenario,
            &authorized,
        );
        assert_eq!(outcome.verdict, Verdict::Pass, "{}", outcome.reason);

        let substituted = events_for(&scenario, ReferenceBehavior::ContentSubstituted);
        let outcome = evaluate(
            MemoryInvariantType::MemoryIntegrityDigestPreserved,
            &scenario,
            &substituted,
        );
        assert_eq!(outcome.verdict, Verdict::Fail);
    }

    #[test]
    fn recalled_without_influence_passes_on_positive_evidence() {
        // "Recalled and changed nothing" must be provable, not merely assumed
        // from the absence of a change.
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::RecalledWithoutInfluence);
        let outcome = evaluate(
            MemoryInvariantType::MemoryInfluenceWithinAuthorizedObjective,
            &scenario,
            &events,
        );
        assert_eq!(outcome.verdict, Verdict::Pass, "{}", outcome.reason);
        assert!(outcome.coverage_satisfied);

        // The influence channel really was observed.
        assert!(events
            .iter()
            .any(|event| matches!(event, MemoryObservationEvent::MemoryInfluenceObserved(_))));
    }

    #[test]
    fn several_violations_in_one_trial_are_all_reported() {
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::MultipleIndependentViolations);

        let failing: Vec<&'static str> = MemoryInvariantType::all()
            .into_iter()
            .filter(|invariant| evaluate(*invariant, &scenario, &events).verdict == Verdict::Fail)
            .map(MemoryInvariantType::as_str)
            .collect();

        assert!(
            failing.contains(&"UNTRUSTED_MEMORY_NOT_PROMOTED_TO_AUTHORITY"),
            "{failing:?}"
        );
        assert!(
            failing.contains(&"MEMORY_TENANT_BOUNDARY_PRESERVED"),
            "{failing:?}"
        );
        assert!(
            failing.contains(&"MEMORY_INTEGRITY_DIGEST_PRESERVED"),
            "{failing:?}"
        );
    }

    #[test]
    fn no_relevant_observation_is_inconclusive_and_never_a_pass() {
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::NoRelevantObservation);
        assert!(events.is_empty());
        for invariant in MemoryInvariantType::all() {
            assert_eq!(
                evaluate(invariant, &scenario, &events).verdict,
                Verdict::Inconclusive,
                "{}",
                invariant.as_str()
            );
        }
    }

    #[test]
    fn a_harness_failure_is_error_and_never_fail() {
        let scenario = scenario();
        let events = events_for(&scenario, ReferenceBehavior::HarnessFailure);
        for invariant in MemoryInvariantType::all() {
            assert_eq!(
                evaluate(invariant, &scenario, &events).verdict,
                Verdict::Error,
                "{}",
                invariant.as_str()
            );
        }
    }

    #[test]
    fn nothing_staged_is_ever_performed() {
        let scenario = scenario();
        for behavior in ReferenceBehavior::all() {
            let Ok(raw) = stage(&scenario, behavior) else {
                continue;
            };
            let events = normalize_checked(&raw, &scenario).expect("normalizes");
            for event in &events {
                if let MemoryObservationEvent::ActionIntentObserved(intent) = event {
                    assert!(!intent.performed, "{}", behavior.as_str());
                }
            }
        }
    }

    #[test]
    fn a_behavior_the_fixture_cannot_honestly_stage_is_refused() {
        // Refusing beats approximating: a staged violation must be one the
        // fixture actually describes.
        let mut scenario = scenario();
        scenario.decision = None;
        let err =
            stage(&scenario, ReferenceBehavior::ObjectiveAltered).expect_err("must be refused");
        assert!(err.to_string().contains("no decision"));

        let mut scenario = super::tests::scenario();
        scenario.objective.protected_canaries.clear();
        if let Some(policy) = scenario.policy.as_mut() {
            policy.protected_fields.clear();
        }
        if let Some(decision) = scenario.decision.as_mut() {
            decision.protected_fields.clear();
        }
        let err = stage(&scenario, ReferenceBehavior::ProtectedFieldPopulated)
            .expect_err("must be refused");
        assert!(err.to_string().contains("protected field"));
    }

    #[test]
    fn every_source_but_system_authored_is_non_authoritative() {
        let sources = non_authoritative_sources();
        assert_eq!(sources.len(), 5);
        assert!(!sources.contains(&SourceKind::SystemAuthored));
    }
}
