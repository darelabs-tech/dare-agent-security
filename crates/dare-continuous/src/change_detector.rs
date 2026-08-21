use std::collections::BTreeSet;

use crate::{
    changeset::{ChangeFact, ChangeType, SecurityChangeSet},
    snapshot::SecurityStateSnapshot,
};

pub fn detect_changes(
    baseline: &SecurityStateSnapshot,
    candidate: &SecurityStateSnapshot,
) -> SecurityChangeSet {
    let before = &baseline.security_state;
    let after = &candidate.security_state;
    let mut changes = Vec::new();

    compare(
        &mut changes,
        ChangeType::SourceCodeChanged,
        "target",
        "source_code",
        before.facts.source_code_digest.as_ref(),
        after.facts.source_code_digest.as_ref(),
    );
    compare(
        &mut changes,
        ChangeType::InventoryChanged,
        "inventory",
        "inventory",
        Some(&before.inventory_digest),
        Some(&after.inventory_digest),
    );
    compare(
        &mut changes,
        ChangeType::AuthorizationChanged,
        "authorization",
        "policy",
        before.facts.authorization_digest.as_ref(),
        after.facts.authorization_digest.as_ref(),
    );
    compare(
        &mut changes,
        ChangeType::CredentialChanged,
        "credentials",
        "credential_set",
        before.facts.credential_digest.as_ref(),
        after.facts.credential_digest.as_ref(),
    );
    compare(
        &mut changes,
        ChangeType::TenantModelChanged,
        "target",
        "tenant_model",
        before.facts.tenant_model_digest.as_ref(),
        after.facts.tenant_model_digest.as_ref(),
    );
    compare(
        &mut changes,
        ChangeType::DependencyChanged,
        "dependencies",
        "dependency_set",
        before.facts.dependency_digest.as_ref(),
        after.facts.dependency_digest.as_ref(),
    );
    compare(
        &mut changes,
        ChangeType::ProfileChanged,
        "profile",
        "assessment_profile",
        Some(&before.profile_digest),
        Some(&after.profile_digest),
    );
    compare(
        &mut changes,
        ChangeType::PropertyRegistryChanged,
        "registry",
        "property_registry",
        Some(&before.property_registry_digest),
        Some(&after.property_registry_digest),
    );
    compare(
        &mut changes,
        ChangeType::RoeChanged,
        "roe",
        "rules_of_engagement",
        before.facts.roe_digest.as_ref(),
        after.facts.roe_digest.as_ref(),
    );
    compare(
        &mut changes,
        ChangeType::GraphChanged,
        "attack_graph",
        "graph",
        Some(&before.attack_graph_digest),
        Some(&after.attack_graph_digest),
    );
    compare(
        &mut changes,
        ChangeType::ValidationChanged,
        "validation",
        "vectors",
        before.facts.validation_vector_digest.as_ref(),
        after.facts.validation_vector_digest.as_ref(),
    );
    compare(
        &mut changes,
        ChangeType::RuntimeEvidenceChanged,
        "evidence",
        "runtime",
        before.facts.runtime_evidence_digest.as_ref(),
        after.facts.runtime_evidence_digest.as_ref(),
    );

    let policy_keys: BTreeSet<_> = before
        .policies
        .keys()
        .chain(after.policies.keys())
        .collect();
    for key in policy_keys {
        compare(
            &mut changes,
            ChangeType::PolicyChanged,
            "policy",
            key,
            before.policies.get(key),
            after.policies.get(key),
        );
    }

    let capability_ids: BTreeSet<_> = before
        .facts
        .capabilities
        .keys()
        .chain(after.facts.capabilities.keys())
        .collect();
    for id in capability_ids {
        let old = before.facts.capabilities.get(id);
        let new = after.facts.capabilities.get(id);
        let change_type = match (old, new) {
            (None, Some(_)) => Some(ChangeType::CapabilityAdded),
            (Some(_), None) => Some(ChangeType::CapabilityRemoved),
            (Some(a), Some(b)) if a != b => Some(ChangeType::CapabilityChanged),
            _ => None,
        };
        if let Some(change_type) = change_type {
            changes.push(ChangeFact {
                change_type,
                source: "inventory.capabilities".to_owned(),
                entity: id.clone(),
                before: old.map(|fact| fact.digest.clone()),
                after: new.map(|fact| fact.digest.clone()),
            });
        }
    }

    if !before.facts.complete || !after.facts.complete {
        changes.push(ChangeFact {
            change_type: ChangeType::Unknown,
            source: "snapshot".to_owned(),
            entity: "security_fact_completeness".to_owned(),
            before: Some(before.facts.complete.to_string()),
            after: Some(after.facts.complete.to_string()),
        });
    }

    changes.sort_by(|a, b| {
        (a.change_type, &a.source, &a.entity).cmp(&(b.change_type, &b.source, &b.entity))
    });
    SecurityChangeSet {
        schema_version: "1".to_owned(),
        baseline_state: before.id.clone(),
        candidate_state: after.id.clone(),
        changes,
    }
}

fn compare(
    output: &mut Vec<ChangeFact>,
    change_type: ChangeType,
    source: &str,
    entity: &str,
    before: Option<&String>,
    after: Option<&String>,
) {
    if before != after {
        output.push(ChangeFact {
            change_type,
            source: source.to_owned(),
            entity: entity.to_owned(),
            before: before.cloned(),
            after: after.cloned(),
        });
    }
}
