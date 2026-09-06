//! Composition with the Cycle 013 and Cycle 015 engines.
//!
//! Cycle 016 owns exactly one question: what happens to a security boundary
//! once the data behind it has been *persisted*. It does not own the question
//! of whether untrusted content acted as an instruction — that is Cycle 013 —
//! and it does not own the question of whose identity an operation runs under —
//! that is Cycle 015. Both engines already exist in this workspace, and this
//! module exists so Cycle 016 composes with them instead of quietly answering
//! their questions a second time with different words.
//!
//! Two failure modes motivate everything here.
//!
//! The first is **restating**. If Cycle 016 re-derived "this external content
//! is untrusted", the workspace would hold two definitions of untrusted that
//! could drift apart, and an operator reading a memory finding would have no
//! way to tell which one produced it. So the mapping below is a projection onto
//! Cycle 013's vocabulary, not a parallel copy of it, and the composed view
//! returns *both* boundaries rather than replacing one with the other.
//!
//! The second is **reinterpreting**. A memory store that decided a `SERVICE`
//! principal was really a user, or that an item belonged to whichever tenant
//! was convenient, would break the isolation Cycle 015 established while
//! reporting nothing at all. [`assert_identity_agreement`] makes that a refusal:
//! where the two models describe the same principal, they must describe it
//! identically, and a divergence stops the evaluation rather than picking a
//! winner.

use dare_identity_security::principal::{Principal as IdentityPrincipal, PrincipalSet};
use dare_prompt_injection::model::InvariantType as InjectionInvariantType;
use dare_prompt_injection::source::{
    InjectionDirection, SourceKind as InjectionSourceKind, TrustLevel as InjectionTrustLevel,
};

use crate::binding::{MemoryContext, MemoryPrincipal, PrincipalKind};
use crate::error::{MemorySecurityError, Result};
use crate::model::MemoryProperty;
use crate::source::{SourceKind, TrustClass, TrustLevel};

// ---------------------------------------------------------------------------
// Cycle 013 — trust-boundary composition
// ---------------------------------------------------------------------------

/// The Cycle 013 content channel a memory source originally arrived through.
///
/// `None` is a real answer, not a gap: content the system authored under policy
/// and content the agent produced itself never crossed an untrusted-content
/// boundary, so no Cycle 013 channel describes them. Naming one anyway would
/// invent an injection surface that was never exercised.
///
/// Both `EXTERNAL_CONTENT` and `IMPORTED_CONTEXT` map to
/// `GENERIC_EXTERNAL_CONTENT` rather than to a document or HTML channel. Cycle
/// 016 records that content came from outside; *which* outside channel it came
/// from is a Cycle 013 scenario detail, and guessing it here would attribute a
/// finding to a surface nobody tested.
pub fn injection_source_for(source: SourceKind) -> Option<InjectionSourceKind> {
    match source {
        SourceKind::UserInput => Some(InjectionSourceKind::UserPrompt),
        SourceKind::ToolOutput | SourceKind::ExternalContent | SourceKind::ImportedContext => {
            Some(InjectionSourceKind::GenericExternalContent)
        }
        SourceKind::SystemAuthored | SourceKind::AgentGenerated => None,
    }
}

/// The Cycle 013 injection direction a memory source corresponds to.
pub fn injection_direction_for(source: SourceKind) -> Option<InjectionDirection> {
    injection_source_for(source).map(InjectionSourceKind::direction)
}

/// The Cycle 013 trust level a memory channel-trust label denotes.
///
/// The two vocabularies are token-identical on purpose, and a test pins that.
/// If one of them ever gains a variant the other lacks, this function stops
/// compiling rather than silently mapping the new case onto an old one.
pub fn injection_trust_level(level: TrustLevel) -> InjectionTrustLevel {
    match level {
        TrustLevel::Trusted => InjectionTrustLevel::Trusted,
        TrustLevel::Untrusted => InjectionTrustLevel::Untrusted,
        TrustLevel::Mixed => InjectionTrustLevel::Mixed,
    }
}

/// Every boundary property that applies to content from this source, in order:
/// the Cycle 013 boundary it crossed on the way in, then the Cycle 016 boundary
/// it crosses on the way into storage.
///
/// The list composes; it never substitutes. Content that entered as untrusted
/// external text is still subject to the Cycle 013 instruction boundary after
/// it has been persisted, and it additionally becomes subject to the write
/// trust boundary. Returning only the memory property would let persistence
/// look like it *discharged* the injection question.
pub fn composed_boundary_properties(source: SourceKind) -> Vec<&'static str> {
    let mut properties = Vec::new();
    if let Some(channel) = injection_source_for(source) {
        properties.push(channel.boundary_property());
    }
    properties.push(MemoryProperty::WriteTrustBoundary.as_str());
    properties
}

/// True when persisting content from this source leaves it attacker-influenceable.
///
/// This is the central claim of the cycle stated as a function of two engines
/// at once: a channel Cycle 013 calls attacker-controlled is still
/// attacker-controlled after a write, because a write records data and confers
/// nothing. Trust can only be raised by an explicit policy grant, never by the
/// act of storage.
///
/// Computed only from the Cycle 013 channel, deliberately: if it consulted the
/// memory-side taxonomy it would agree with itself by construction and prove
/// nothing. A test compares it against
/// [`SourceKind::is_externally_influenceable`], so the two models have to keep
/// agreeing independently.
pub fn persistence_preserves_attacker_control(source: SourceKind) -> bool {
    injection_source_for(source).is_some()
}

/// The ceiling a source may reach after persistence, expressed as a check
/// rather than a claim.
///
/// Returns an error naming the disagreement if a source Cycle 013 treats as an
/// untrusted channel were ever given a policy-authoritative ceiling here. It is
/// a guard against the two engines drifting apart in a future edit, and a test
/// runs it over every source.
pub fn assert_ceiling_agrees_with_injection_model(source: SourceKind) -> Result<()> {
    if injection_source_for(source).is_some()
        && source.default_trust_ceiling() == TrustClass::TrustedPolicy
    {
        return Err(MemorySecurityError::invalid(format!(
            "source `{}` is an untrusted content channel under Cycle 013 but carries a \
             policy-authoritative default ceiling here; the two models disagree",
            source.as_str()
        )));
    }
    Ok(())
}

/// The Cycle 013 invariant names, read from that crate rather than copied.
///
/// Used to prove the two engines answer disjoint questions. Nothing in the
/// evaluator calls this; it exists so an invariant added to either side cannot
/// quietly shadow one on the other, and reading the list at its source is what
/// keeps the check from going stale against a hand-maintained copy.
pub fn injection_invariant_names() -> Vec<&'static str> {
    InjectionInvariantType::all()
        .iter()
        .map(|invariant| invariant.as_str())
        .collect()
}

// ---------------------------------------------------------------------------
// Cycle 015 — identity and tenant composition
// ---------------------------------------------------------------------------

/// Build a memory principal from a Cycle 015 principal.
///
/// Refuses a principal with no tenant. Cycle 015 permits `tenant_id: None`
/// because plenty of identity questions are answerable without one; memory
/// isolation is not one of them. Defaulting the tenant — to empty, to the
/// acting tenant, to anything — would place an item in a partition nobody
/// declared, and every later boundary check would then be measured against an
/// invented fact.
///
/// Namespaces are supplied by the caller rather than derived, because Cycle 015
/// has no namespace axis and inferring one from roles would be a guess.
pub fn memory_principal_from_identity(
    principal: &IdentityPrincipal,
    namespaces: Vec<String>,
) -> Result<MemoryPrincipal> {
    let tenant_id = principal.tenant_id.clone().ok_or_else(|| {
        MemorySecurityError::refusal(format!(
            "identity principal `{}` declares no tenant; memory isolation cannot be evaluated \
             against a tenant that was never stated",
            principal.id
        ))
    })?;

    let memory_principal = MemoryPrincipal {
        principal_id: principal.id.clone(),
        kind: principal.kind,
        tenant_id,
        namespaces,
        display_label: principal.display_label.clone(),
    };
    memory_principal.validate()?;
    Ok(memory_principal)
}

/// Refuse a memory context that describes a shared principal differently from
/// the Cycle 015 principal set.
///
/// Only ids present in both are compared: a memory context may legitimately
/// declare principals the identity scenario never mentioned, and an identity
/// scenario may name principals no memory item belongs to. Where they overlap,
/// though, kind and tenant must agree exactly. A memory store that re-labelled
/// an `AGENT` as a `HUMAN`, or moved a principal into a neighbouring tenant,
/// would defeat Cycle 015's boundaries while producing no finding of its own —
/// so the divergence stops the run instead of being resolved in either
/// direction.
pub fn assert_identity_agreement(set: &PrincipalSet, context: &MemoryContext) -> Result<()> {
    for memory_principal in &context.principals {
        let Some(identity_principal) = set.get(&memory_principal.principal_id) else {
            continue;
        };

        if identity_principal.kind != memory_principal.kind {
            return Err(MemorySecurityError::refusal(format!(
                "principal `{}` is a {} in the identity set and a {} in the memory context; \
                 memory security may not reinterpret an identity",
                memory_principal.principal_id,
                identity_principal.kind.as_str(),
                memory_principal.kind.as_str()
            )));
        }

        match identity_principal.tenant_id.as_deref() {
            Some(tenant) if tenant != memory_principal.tenant_id => {
                return Err(MemorySecurityError::refusal(format!(
                    "principal `{}` belongs to tenant `{}` in the identity set and to `{}` in \
                     the memory context; memory security may not reassign tenant ownership",
                    memory_principal.principal_id, tenant, memory_principal.tenant_id
                )));
            }
            Some(_) => {}
            None => {
                return Err(MemorySecurityError::refusal(format!(
                    "principal `{}` declares a tenant in the memory context but none in the \
                     identity set; memory security may not supply a tenant identity did not state",
                    memory_principal.principal_id
                )));
            }
        }
    }
    Ok(())
}

/// Whether the acting principal can originate authority, answered by Cycle 015.
///
/// Delegated rather than reimplemented. Cycle 016 has opinions about what
/// recalled memory may influence; it has none about which kinds of principal
/// are authority sources, and borrowing the answer keeps a `SERVICE` principal
/// from becoming an authority here while remaining a non-authority there.
pub fn acting_principal_originates_authority(context: &MemoryContext) -> Result<bool> {
    Ok(context.acting()?.kind.originates_authority())
}

/// The Cycle 015 principal kinds, unchanged.
///
/// Exposed so a caller never has to build its own list and risk it going stale
/// against the identity crate.
pub fn principal_kinds() -> [PrincipalKind; 4] {
    PrincipalKind::all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::tests::valid_context;
    use crate::model::MemoryInvariantType;
    use crate::source::PoisoningFamily;
    use dare_prompt_injection::source::InjectionFamily;

    // -- Cycle 013 composition -------------------------------------------

    #[test]
    fn every_memory_source_either_names_a_cycle_013_channel_or_explains_why_not() {
        for source in SourceKind::all() {
            match injection_source_for(source) {
                Some(_) => assert!(
                    source != SourceKind::SystemAuthored && source != SourceKind::AgentGenerated,
                    "{source:?} should not map to an untrusted content channel"
                ),
                None => assert!(
                    matches!(
                        source,
                        SourceKind::SystemAuthored | SourceKind::AgentGenerated
                    ),
                    "{source:?} left the injection channel unmapped without cause"
                ),
            }
        }
    }

    #[test]
    fn persisting_untrusted_content_does_not_discharge_the_injection_boundary() {
        // The composed view keeps both properties. If persistence were treated
        // as resolving the injection question, the Cycle 013 property would
        // drop out of this list and an operator would read the memory verdict
        // as covering ground it never covered.
        let composed = composed_boundary_properties(SourceKind::ExternalContent);
        assert_eq!(
            composed,
            vec![
                "AGENT.GOAL.EXTERNAL_CONTENT_INSTRUCTION_BOUNDARY",
                "AGENT.MEMORY.WRITE_TRUST_BOUNDARY",
            ]
        );

        let direct = composed_boundary_properties(SourceKind::UserInput);
        assert_eq!(
            direct,
            vec![
                "AGENT.GOAL.USER_INPUT_INSTRUCTION_BOUNDARY",
                "AGENT.MEMORY.WRITE_TRUST_BOUNDARY",
            ]
        );
    }

    #[test]
    fn system_authored_content_composes_with_no_injection_boundary() {
        // Not an omission: nothing crossed a Cycle 013 channel, so naming one
        // would report an untested surface.
        assert_eq!(
            composed_boundary_properties(SourceKind::SystemAuthored),
            vec!["AGENT.MEMORY.WRITE_TRUST_BOUNDARY"]
        );
    }

    #[test]
    fn the_two_models_agree_on_which_sources_are_attacker_influenceable() {
        // One side is derived from the Cycle 013 channel map, the other from
        // the Cycle 016 taxonomy. They are computed independently, so this is a
        // real cross-check rather than a tautology: a future edit that loosened
        // either side alone would fail here.
        for source in SourceKind::all() {
            assert_eq!(
                persistence_preserves_attacker_control(source),
                source.is_externally_influenceable(),
                "the two models disagree about {source:?}"
            );
        }
    }

    #[test]
    fn no_untrusted_channel_carries_a_policy_authoritative_ceiling() {
        for source in SourceKind::all() {
            assert_ceiling_agrees_with_injection_model(source).expect("models agree");
        }

        // Exactly one source may be policy-authoritative, and it is the one
        // that never crossed an untrusted channel.
        let authoritative: Vec<_> = SourceKind::all()
            .into_iter()
            .filter(|source| source.default_trust_ceiling() == TrustClass::TrustedPolicy)
            .collect();
        assert_eq!(authoritative, vec![SourceKind::SystemAuthored]);
        assert!(injection_source_for(SourceKind::SystemAuthored).is_none());
    }

    #[test]
    fn the_two_trust_level_vocabularies_are_token_identical() {
        for level in TrustLevel::all() {
            assert_eq!(level.as_str(), injection_trust_level(level).as_str());
        }
    }

    #[test]
    fn memory_invariants_and_injection_invariants_are_disjoint() {
        // Cycle 016 does not re-ask a Cycle 013 question under a new name. A
        // shared name would make two engines look like one, and a reader could
        // not tell which produced a finding.
        let injection = injection_invariant_names();
        for invariant in MemoryInvariantType::all() {
            assert!(
                !injection.contains(&invariant.as_str()),
                "memory invariant `{}` collides with a Cycle 013 invariant",
                invariant.as_str()
            );
        }
        assert_eq!(injection.len(), 6);
    }

    #[test]
    fn memory_families_and_injection_families_are_disjoint() {
        let injection: Vec<&str> = InjectionFamily::all()
            .iter()
            .map(|family| family.as_str())
            .collect();
        for family in PoisoningFamily::all() {
            assert!(
                !injection.contains(&family.as_str()),
                "poisoning family `{}` collides with an injection family",
                family.as_str()
            );
        }
    }

    #[test]
    fn direction_is_borrowed_from_cycle_013_not_recomputed() {
        assert_eq!(
            injection_direction_for(SourceKind::UserInput),
            Some(InjectionDirection::Direct)
        );
        assert_eq!(
            injection_direction_for(SourceKind::ToolOutput),
            Some(InjectionDirection::Indirect)
        );
        assert_eq!(injection_direction_for(SourceKind::SystemAuthored), None);
    }

    // -- Cycle 015 composition -------------------------------------------

    fn identity_set() -> PrincipalSet {
        serde_json::from_value(serde_json::json!({
            "schema_version": "1",
            "set_id": "set-support",
            "principals": [
                {"id": "user-7", "kind": "HUMAN", "tenant_id": "tenant-a"},
                {"id": "agent-1", "kind": "AGENT", "tenant_id": "tenant-a"},
                {"id": "user-9", "kind": "HUMAN", "tenant_id": "tenant-b"}
            ],
            "bindings": {
                "initiating_principal_id": "user-7",
                "effective_principal_id": "user-7"
            }
        }))
        .expect("fixture decodes")
    }

    #[test]
    fn an_agreeing_identity_set_and_memory_context_compose() {
        assert_identity_agreement(&identity_set(), &valid_context()).expect("they agree");
    }

    #[test]
    fn relabelling_a_principals_kind_in_memory_is_refused() {
        let mut context = valid_context();
        // agent-1 is an AGENT in the identity set. Calling it a HUMAN here
        // would make it an authority origin under Cycle 015's own rule.
        context.principals[1].kind = PrincipalKind::Human;

        let err = assert_identity_agreement(&identity_set(), &context).expect_err("refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("agent-1"));
        assert!(err.to_string().contains("may not reinterpret an identity"));
    }

    #[test]
    fn moving_a_principal_into_another_tenant_in_memory_is_refused() {
        let mut context = valid_context();
        context.principals[2].tenant_id = "tenant-a".to_owned();

        let err = assert_identity_agreement(&identity_set(), &context).expect_err("refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("tenant-b"));
    }

    #[test]
    fn memory_may_not_supply_a_tenant_the_identity_set_left_unstated() {
        let mut set = identity_set();
        set.principals[0].tenant_id = None;

        let err = assert_identity_agreement(&set, &valid_context()).expect_err("refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("may not supply a tenant"));
    }

    #[test]
    fn principals_only_one_model_declares_are_left_alone() {
        // A memory context routinely names principals an identity scenario has
        // no reason to mention. That is not a disagreement.
        let mut set = identity_set();
        set.principals.retain(|principal| principal.id != "user-9");
        assert_identity_agreement(&set, &valid_context()).expect("no overlap, no conflict");
    }

    #[test]
    fn an_identity_principal_without_a_tenant_cannot_become_a_memory_principal() {
        let mut principal = identity_set().principals[0].clone();
        principal.tenant_id = None;

        let err = memory_principal_from_identity(&principal, vec!["ns-support".to_owned()])
            .expect_err("refused");
        assert!(err.is_refusal());
        assert!(err.to_string().contains("no tenant"));
    }

    #[test]
    fn converting_an_identity_principal_preserves_kind_and_tenant_exactly() {
        let principal = identity_set().principals[1].clone();
        let converted = memory_principal_from_identity(&principal, vec!["ns-support".to_owned()])
            .expect("converts");

        assert_eq!(converted.principal_id, "agent-1");
        assert_eq!(converted.kind, PrincipalKind::Agent);
        assert_eq!(converted.tenant_id, "tenant-a");
        assert_eq!(converted.namespaces, vec!["ns-support".to_owned()]);
    }

    #[test]
    fn authority_origination_is_answered_by_cycle_015() {
        let mut context = valid_context();
        assert!(acting_principal_originates_authority(&context).expect("acting principal declared"));

        context.acting_principal_id = "agent-1".to_owned();
        assert!(!acting_principal_originates_authority(&context).expect("declared"));
    }

    #[test]
    fn memory_security_adds_no_principal_kinds() {
        assert_eq!(principal_kinds().len(), 4);
        assert_eq!(
            principal_kinds().map(|kind| kind.as_str()),
            ["HUMAN", "AGENT", "WORKLOAD", "SERVICE"]
        );
    }

    #[test]
    fn a_converted_principal_with_a_hostile_namespace_is_refused() {
        let principal = identity_set().principals[0].clone();
        let err = memory_principal_from_identity(&principal, vec!["../../etc/passwd".to_owned()])
            .expect_err("refused");
        assert!(err.is_refusal());
    }
}
