use std::collections::BTreeSet;

use crate::{
    dependencies::ALL_PROPERTY_IDS,
    plan::{ArtifactKind, ContinuousRevalidationPlan, PlanAction, PlanItem},
    snapshot::SecurityStateSnapshot,
};

pub fn expand_full_fallback(
    plan: &mut ContinuousRevalidationPlan,
    candidate: &SecurityStateSnapshot,
) {
    let mut surface: BTreeSet<(ArtifactKind, String)> = plan
        .items
        .iter()
        .map(|item| (item.kind, item.id.clone()))
        .collect();
    surface.extend(
        ALL_PROPERTY_IDS
            .iter()
            .map(|id| (ArtifactKind::Property, (*id).to_owned())),
    );
    surface.extend(
        candidate
            .security_state
            .attack_paths
            .keys()
            .map(|id| (ArtifactKind::Path, id.clone())),
    );
    surface.extend(
        candidate
            .security_state
            .validation_results
            .keys()
            .map(|id| (ArtifactKind::Vector, id.clone())),
    );
    plan.items = surface
        .into_iter()
        .map(|(kind, id)| PlanItem {
            kind,
            id,
            action: PlanAction::Revalidate,
            reason: "full fallback because impact or dependency completeness is unknown".to_owned(),
        })
        .collect();
    plan.full_fallback = true;
}
