//! Composition with Cycles 013, 015 and 016.
//!
//! Cycle 017 borders on three engines that already exist, and the risk in every
//! case is the same: answering their question a second time, in different
//! words, so that the workspace ends up with two definitions that agree until
//! they quietly do not.
//!
//! **Cycle 013** owns whether untrusted content acted as an instruction, and
//! stays the final judge of it. Cycle 017 projects retrieval sources onto that
//! vocabulary and reports *both* boundaries — the injection boundary the
//! content crossed on the way in, and the retrieval boundary it crosses on the
//! way out. Retrieval adds a boundary; it discharges none.
//!
//! **Cycle 015** owns principal and tenant identity. Its `PrincipalKind` is
//! re-exported rather than redefined, and where the two models describe the
//! same principal they must describe it identically —
//! [`assert_identity_agreement`] makes a divergence stop the run rather than
//! resolving it in either direction.
//!
//! **Cycle 016** owns persisted memory. This is the boundary most likely to be
//! blurred, because retrieved content and recalled memory look alike in a
//! transcript. They are not the same: retrieval reads from an index, memory
//! reads from something the agent previously stored. Retrieved content becomes
//! memory only through a separate, explicit memory event, and
//! [`retrieval_is_not_memory`] states the rule the tests hold the code to.

use dare_identity_security::principal::{Principal as IdentityPrincipal, PrincipalSet};
use dare_memory_security::model::MemoryInvariantType;
use dare_prompt_injection::model::InvariantType as InjectionInvariantType;
use dare_prompt_injection::source::{
    InjectionDirection, SourceKind as InjectionSourceKind, TrustLevel as InjectionTrustLevel,
};

use crate::error::{RagSecurityError, Result};
use crate::model::RagProperty;

use crate::query::{PrincipalKind, RetrievalContext, RetrievalPrincipal};
use crate::source::{DocumentSourceKind, DocumentTrustClass, TrustLevel};

// ---------------------------------------------------------------------------
// Cycle 013 — trust-boundary composition
// ---------------------------------------------------------------------------

/// The Cycle 013 content channel a retrieval source originally arrived through.
///
/// `None` is a real answer, not a gap: content the system authored under policy
/// and content the agent produced itself never crossed an untrusted-content
/// boundary, so no Cycle 013 channel describes them. Naming one anyway would
/// invent an injection surface that was never exercised.
///
/// Everything ingested from outside maps to `GENERIC_EXTERNAL_CONTENT` rather
/// than to a document or HTML channel. Cycle 017 records that content came from
/// outside; *which* outside channel is a Cycle 013 scenario detail, and
/// guessing would attribute a finding to a surface nobody tested.
pub fn injection_source_for(source: DocumentSourceKind) -> Option<InjectionSourceKind> {
    match source {
        DocumentSourceKind::TenantUpload
        | DocumentSourceKind::ExternalIngested
        | DocumentSourceKind::ImportedCorpus
        | DocumentSourceKind::ToolOutput => Some(InjectionSourceKind::GenericExternalContent),
        DocumentSourceKind::InternalAuthored | DocumentSourceKind::AgentGenerated => None,
    }
}

/// The Cycle 013 injection direction a retrieval source corresponds to.
///
/// Always indirect when it maps at all: retrieved content reaches the agent
/// through a document, never as something a user typed.
pub fn injection_direction_for(source: DocumentSourceKind) -> Option<InjectionDirection> {
    injection_source_for(source).map(InjectionSourceKind::direction)
}

/// The Cycle 013 trust level a retrieval channel-trust label denotes.
///
/// The two vocabularies are token-identical on purpose, and a test pins that.
/// If one of them gains a variant the other lacks, this function stops
/// compiling rather than silently mapping the new case onto an old one.
pub fn injection_trust_level(level: TrustLevel) -> InjectionTrustLevel {
    match level {
        TrustLevel::Trusted => InjectionTrustLevel::Trusted,
        TrustLevel::Untrusted => InjectionTrustLevel::Untrusted,
        TrustLevel::Mixed => InjectionTrustLevel::Mixed,
    }
}

/// Every boundary property that applies to content from this source, in order:
/// the Cycle 013 boundary it crossed on the way in, then the Cycle 017 boundary
/// it crosses on the way out of a retriever.
///
/// The list composes; it never substitutes. Content ingested as untrusted
/// external text is still subject to the Cycle 013 instruction boundary after
/// it has been retrieved, and it additionally becomes subject to the retrieval
/// content-trust boundary. Returning only the retrieval property would let
/// retrieval look like it *discharged* the injection question.
pub fn composed_boundary_properties(source: DocumentSourceKind) -> Vec<&'static str> {
    let mut properties = Vec::new();
    if let Some(channel) = injection_source_for(source) {
        properties.push(channel.boundary_property());
    }
    properties.push(RagProperty::ContentTrustBoundary.as_str());
    properties
}

/// True when retrieving content from this source leaves it
/// attacker-influenceable.
///
/// Computed only from the Cycle 013 channel, deliberately: if it consulted the
/// retrieval taxonomy it would agree with itself by construction and prove
/// nothing. A test compares it against
/// [`DocumentSourceKind::is_externally_influenceable`], so the two models have
/// to keep agreeing independently.
pub fn retrieval_preserves_attacker_control(source: DocumentSourceKind) -> bool {
    injection_source_for(source).is_some()
}

/// Guard against the two trust models drifting apart.
///
/// Returns an error naming the disagreement if a source Cycle 013 treats as an
/// untrusted channel were ever given a policy-authoritative ceiling here.
pub fn assert_ceiling_agrees_with_injection_model(source: DocumentSourceKind) -> Result<()> {
    if injection_source_for(source).is_some()
        && source.default_trust_ceiling() == DocumentTrustClass::TrustedPolicy
    {
        return Err(RagSecurityError::invalid(format!(
            "source `{}` is an untrusted content channel under Cycle 013 but carries a \
             policy-authoritative default ceiling here; the two models disagree",
            source.as_str()
        )));
    }
    Ok(())
}

/// The Cycle 013 invariant names, read from that crate rather than copied.
///
/// Used to prove the two engines answer disjoint questions. Reading the list at
/// its source is what keeps the check from going stale against a
/// hand-maintained copy.
pub fn injection_invariant_names() -> Vec<&'static str> {
    InjectionInvariantType::all()
        .iter()
        .map(|invariant| invariant.as_str())
        .collect()
}

// ---------------------------------------------------------------------------
// Cycle 015 — identity composition
// ---------------------------------------------------------------------------

/// Build a retrieval principal from a Cycle 015 principal.
///
/// Refuses a principal with no tenant. Cycle 015 permits `tenant_id: None`
/// because plenty of identity questions are answerable without one; retrieval
/// isolation is not one of them. Defaulting the tenant — to empty, to the
/// acting tenant, to anything — would place a principal in a boundary nobody
/// declared, and every later isolation check would be measured against an
/// invented fact.
pub fn retrieval_principal_from_identity(
    principal: &IdentityPrincipal,
) -> Result<RetrievalPrincipal> {
    let tenant_id = principal.tenant_id.clone().ok_or_else(|| {
        RagSecurityError::refusal(format!(
            "identity principal `{}` declares no tenant; retrieval isolation cannot be evaluated \
             against a tenant that was never stated",
            principal.id
        ))
    })?;

    let retrieval_principal = RetrievalPrincipal {
        principal_id: principal.id.clone(),
        kind: principal.kind,
        tenant_id,
        display_label: principal.display_label.clone(),
    };
    retrieval_principal.validate()?;
    Ok(retrieval_principal)
}

/// Refuse a retrieval context that describes a shared principal differently
/// from the Cycle 015 principal set.
///
/// Only ids present in both are compared: a retrieval context may legitimately
/// declare principals the identity scenario never mentioned, and vice versa.
/// Where they overlap, kind and tenant must agree exactly. A retriever that
/// re-labelled an `AGENT` as a `HUMAN`, or moved a principal into a
/// neighbouring tenant, would defeat Cycle 015's boundaries while producing no
/// finding of its own.
pub fn assert_identity_agreement(set: &PrincipalSet, context: &RetrievalContext) -> Result<()> {
    for principal in &context.principals {
        let Some(identity_principal) = set.get(&principal.principal_id) else {
            continue;
        };

        if identity_principal.kind != principal.kind {
            return Err(RagSecurityError::refusal(format!(
                "principal `{}` is a {} in the identity set and a {} in the retrieval context; \
                 retrieval may not reinterpret an identity",
                principal.principal_id,
                identity_principal.kind.as_str(),
                principal.kind.as_str()
            )));
        }

        match identity_principal.tenant_id.as_deref() {
            Some(tenant) if tenant != principal.tenant_id => {
                return Err(RagSecurityError::refusal(format!(
                    "principal `{}` belongs to tenant `{}` in the identity set and to `{}` in \
                     the retrieval context; retrieval may not reassign tenant ownership",
                    principal.principal_id, tenant, principal.tenant_id
                )));
            }
            Some(_) => {}
            None => {
                return Err(RagSecurityError::refusal(format!(
                    "principal `{}` declares a tenant in the retrieval context but none in the \
                     identity set; retrieval may not supply a tenant identity did not state",
                    principal.principal_id
                )));
            }
        }
    }
    Ok(())
}

/// Whether the acting principal can originate authority, answered by Cycle 015.
///
/// Delegated rather than reimplemented, so a `SERVICE` principal cannot become
/// an authority here while remaining a non-authority there.
pub fn acting_principal_originates_authority(context: &RetrievalContext) -> Result<bool> {
    Ok(context.acting()?.kind.originates_authority())
}

/// The Cycle 015 principal kinds, unchanged.
pub fn principal_kinds() -> [PrincipalKind; 4] {
    PrincipalKind::all()
}

// ---------------------------------------------------------------------------
// Cycle 016 — memory separation
// ---------------------------------------------------------------------------

/// The rule keeping retrieval and memory apart, stated where it is tested.
///
/// Retrieved content is not persisted memory. It becomes memory only when a
/// separate memory event stores it — which is Cycle 016's question and not this
/// cycle's. Cycle 017 records no memory event of any kind: there is no write,
/// no store and no lifecycle in its observation model, and a test asserts that
/// absence rather than trusting it.
pub const RETRIEVAL_IS_NOT_MEMORY: &str =
    "retrieved_content != persisted_memory; retrieval reads an index, memory reads what the \
     agent previously stored, and content crosses from one to the other only through an \
     explicit memory event this cycle neither produces nor records";

/// The Cycle 016 invariant names, read from that crate rather than copied.
pub fn memory_invariant_names() -> Vec<&'static str> {
    MemoryInvariantType::all()
        .iter()
        .map(|invariant| invariant.as_str())
        .collect()
}

/// Whether any Cycle 017 observation could be read as a memory event.
///
/// Always false, and a test pins it by inspecting the serialized event model
/// rather than by asserting the intent. If a future edit added a write or
/// persistence event to this cycle, that test fails and the boundary is
/// restated deliberately rather than crossed by accident.
pub fn retrieval_is_not_memory() -> &'static str {
    RETRIEVAL_IS_NOT_MEMORY
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RagInvariantType;
    use crate::query::tests::valid_context;
    use crate::source::RetrievalFamily;
    use dare_prompt_injection::source::InjectionFamily;

    // -- Cycle 013 composition -------------------------------------------

    #[test]
    fn every_retrieval_source_either_names_a_cycle_013_channel_or_explains_why_not() {
        for source in DocumentSourceKind::all() {
            match injection_source_for(source) {
                Some(_) => assert!(
                    source != DocumentSourceKind::InternalAuthored
                        && source != DocumentSourceKind::AgentGenerated,
                    "{source:?} should not map to an untrusted content channel"
                ),
                None => assert!(
                    matches!(
                        source,
                        DocumentSourceKind::InternalAuthored | DocumentSourceKind::AgentGenerated
                    ),
                    "{source:?} left the injection channel unmapped without cause"
                ),
            }
        }
    }

    #[test]
    fn retrieving_untrusted_content_does_not_discharge_the_injection_boundary() {
        // The composed view keeps both properties. If retrieval were treated as
        // resolving the injection question, the Cycle 013 property would drop
        // out and an operator would read the retrieval verdict as covering
        // ground it never covered.
        let composed = composed_boundary_properties(DocumentSourceKind::ExternalIngested);
        assert_eq!(
            composed,
            vec![
                "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY",
                "AGENT.RAG.CONTENT_TRUST_BOUNDARY",
            ]
        );
    }

    #[test]
    fn internally_authored_content_composes_with_no_injection_boundary() {
        // Not an omission: nothing crossed a Cycle 013 channel, so naming one
        // would report an untested surface.
        assert_eq!(
            composed_boundary_properties(DocumentSourceKind::InternalAuthored),
            vec!["AGENT.RAG.CONTENT_TRUST_BOUNDARY"]
        );
    }

    #[test]
    fn the_two_models_agree_on_which_sources_are_attacker_influenceable() {
        // One side is derived from the Cycle 013 channel map, the other from
        // the Cycle 017 taxonomy. They are computed independently, so this is a
        // real cross-check rather than a tautology.
        for source in DocumentSourceKind::all() {
            assert_eq!(
                retrieval_preserves_attacker_control(source),
                source.is_externally_influenceable(),
                "the two models disagree about {source:?}"
            );
        }
    }

    #[test]
    fn no_untrusted_channel_carries_a_policy_authoritative_ceiling() {
        for source in DocumentSourceKind::all() {
            assert_ceiling_agrees_with_injection_model(source).expect("models agree");
        }

        let authoritative: Vec<_> = DocumentSourceKind::all()
            .into_iter()
            .filter(|source| source.default_trust_ceiling() == DocumentTrustClass::TrustedPolicy)
            .collect();
        assert_eq!(authoritative, vec![DocumentSourceKind::InternalAuthored]);
        assert!(injection_source_for(DocumentSourceKind::InternalAuthored).is_none());
    }

    #[test]
    fn retrieved_content_is_always_indirect_in_the_cycle_013_sense() {
        // It reaches the agent through a document, never as something a user
        // typed, so it can never map to the direct channel.
        for source in DocumentSourceKind::all() {
            if let Some(direction) = injection_direction_for(source) {
                assert_eq!(direction, InjectionDirection::Indirect, "{source:?}");
            }
        }
    }

    #[test]
    fn the_two_trust_level_vocabularies_are_token_identical() {
        for level in TrustLevel::all() {
            assert_eq!(level.as_str(), injection_trust_level(level).as_str());
        }
    }

    #[test]
    fn retrieval_invariants_and_injection_invariants_are_disjoint() {
        // Cycle 017 does not re-ask a Cycle 013 question under a new name. A
        // shared name would make two engines look like one, and a reader could
        // not tell which produced a finding.
        let injection = injection_invariant_names();
        for invariant in RagInvariantType::all() {
            assert!(
                !injection.contains(&invariant.as_str()),
                "retrieval invariant `{}` collides with a Cycle 013 invariant",
                invariant.as_str()
            );
        }
        assert_eq!(injection.len(), 6);
    }

    #[test]
    fn retrieval_families_and_injection_families_are_disjoint() {
        let injection: Vec<&str> = InjectionFamily::all()
            .iter()
            .map(|family| family.as_str())
            .collect();
        for family in RetrievalFamily::all() {
            assert!(
                !injection.contains(&family.as_str()),
                "retrieval family `{}` collides with an injection family",
                family.as_str()
            );
        }
    }

    // -- Cycle 015 composition -------------------------------------------

    fn identity_set() -> PrincipalSet {
        serde_json::from_value(serde_json::json!({
            "schema_version": "1",
            "set_id": "set-retrieval",
            "principals": [
                {"id": "user-7", "kind": "HUMAN", "tenant_id": "tenant-a"},
                {"id": "agent-1", "kind": "AGENT", "tenant_id": "tenant-a"},
                {"id": "user-11", "kind": "HUMAN", "tenant_id": "tenant-b"}
            ],
            "bindings": {
                "initiating_principal_id": "user-7",
                "effective_principal_id": "user-7"
            }
        }))
        .expect("fixture decodes")
    }

    #[test]
    fn an_agreeing_identity_set_and_retrieval_context_compose() {
        assert_identity_agreement(&identity_set(), &valid_context()).expect("they agree");
    }

    #[test]
    fn relabelling_a_principals_kind_in_retrieval_is_refused() {
        let mut context = valid_context();
        // agent-1 is an AGENT in the identity set. Calling it a HUMAN here
        // would make it an authority origin under Cycle 015's own rule.
        context.principals[1].kind = PrincipalKind::Human;

        let err = assert_identity_agreement(&identity_set(), &context).expect_err("refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("may not reinterpret an identity"));
    }

    #[test]
    fn moving_a_principal_into_another_tenant_in_retrieval_is_refused() {
        let mut context = valid_context();
        context.principals[3].tenant_id = "tenant-a".to_owned();

        let err = assert_identity_agreement(&identity_set(), &context).expect_err("refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("tenant-b"));
    }

    #[test]
    fn retrieval_may_not_supply_a_tenant_the_identity_set_left_unstated() {
        let mut set = identity_set();
        set.principals[0].tenant_id = None;

        let err = assert_identity_agreement(&set, &valid_context()).expect_err("refused");
        assert!(err.to_string().contains("may not supply a tenant"));
    }

    #[test]
    fn principals_only_one_model_declares_are_left_alone() {
        // A retrieval context routinely names principals an identity scenario
        // has no reason to mention. That is not a disagreement.
        let mut set = identity_set();
        set.principals.retain(|principal| principal.id != "user-11");
        assert_identity_agreement(&set, &valid_context()).expect("no overlap, no conflict");
    }

    #[test]
    fn an_identity_principal_without_a_tenant_cannot_become_a_retrieval_principal() {
        let mut principal = identity_set().principals[0].clone();
        principal.tenant_id = None;
        let err = retrieval_principal_from_identity(&principal).expect_err("refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("no tenant"));
    }

    #[test]
    fn converting_an_identity_principal_preserves_kind_and_tenant_exactly() {
        let principal = identity_set().principals[1].clone();
        let converted = retrieval_principal_from_identity(&principal).expect("converts");
        assert_eq!(converted.principal_id, "agent-1");
        assert_eq!(converted.kind, PrincipalKind::Agent);
        assert_eq!(converted.tenant_id, "tenant-a");
    }

    #[test]
    fn authority_origination_is_answered_by_cycle_015() {
        let mut context = valid_context();
        assert!(acting_principal_originates_authority(&context).expect("declared"));

        context.acting_principal_id = "agent-1".to_owned();
        assert!(!acting_principal_originates_authority(&context).expect("declared"));
    }

    #[test]
    fn retrieval_adds_no_principal_kinds() {
        assert_eq!(principal_kinds().len(), 4);
        assert_eq!(
            principal_kinds().map(|kind| kind.as_str()),
            ["HUMAN", "AGENT", "WORKLOAD", "SERVICE"]
        );
    }

    // -- Cycle 016 separation --------------------------------------------

    #[test]
    fn retrieval_invariants_and_memory_invariants_are_disjoint() {
        // The two cycles answer adjacent questions about different things.
        // A shared invariant name would let a retrieval finding be read as a
        // memory finding.
        let memory = memory_invariant_names();
        for invariant in RagInvariantType::all() {
            assert!(
                !memory.contains(&invariant.as_str()),
                "retrieval invariant `{}` collides with a Cycle 016 invariant",
                invariant.as_str()
            );
        }
        assert_eq!(memory.len(), 12);
    }

    #[test]
    fn no_retrieval_observation_can_be_read_as_a_memory_event() {
        // Asserted against the serialized model rather than against intent. If
        // a future edit added a write, store or lifecycle event to this cycle,
        // this fails and the boundary is restated deliberately.
        let scenario = crate::harness::tests::scenario();
        let raw = crate::simulated::stage(&scenario, crate::model::ReferenceBehavior::Compliant)
            .expect("stages");
        let events = crate::harness::normalize_checked(&raw, &scenario).expect("normalizes");
        let serialized = serde_json::to_string(&events).expect("serializes");

        for memory_shape in [
            "MEMORY_WRITE",
            "MEMORY_RECALL",
            "MEMORY_SNAPSHOT",
            "\"persisted\"",
            "\"stored_at\"",
            "\"lifecycle\"",
        ] {
            assert!(
                !serialized.contains(memory_shape),
                "a retrieval observation carries `{memory_shape}`, which reads as a memory event"
            );
        }
    }

    #[test]
    fn the_memory_separation_rule_is_stated_where_it_is_tested() {
        let rule = retrieval_is_not_memory();
        assert!(rule.contains("retrieved_content != persisted_memory"));
        assert!(rule.contains("explicit memory event"));
    }

    #[test]
    fn retrieval_and_memory_taxonomies_do_not_share_a_property_namespace() {
        // AGENT.RAG.* and AGENT.MEMORY.* are separate families in the registry.
        for property in RagProperty::all() {
            assert!(property.as_str().starts_with("AGENT.RAG."));
            assert!(!property.as_str().starts_with("AGENT.MEMORY."));
        }
    }
}
