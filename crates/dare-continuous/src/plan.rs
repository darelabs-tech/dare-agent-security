use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    canonical::digest, changeset::SecurityChangeSet, impact::ImpactResolution,
    snapshot::SecurityStateSnapshot, Result,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactKind {
    Property,
    Path,
    Vector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PlanAction {
    Revalidate,
    Reuse,
    Invalidate,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanItem {
    pub kind: ArtifactKind,
    pub id: String,
    pub action: PlanAction,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuousRevalidationPlan {
    pub schema_version: String,
    pub id: String,
    pub baseline_state: String,
    pub candidate_state: String,
    pub change_set_digest: String,
    pub full_fallback: bool,
    pub items: Vec<PlanItem>,
}

pub fn build_plan(
    changes: &SecurityChangeSet,
    impact: &ImpactResolution,
    baseline: &SecurityStateSnapshot,
    candidate: &SecurityStateSnapshot,
) -> Result<ContinuousRevalidationPlan> {
    let change_set_digest = digest(changes)?;
    let mut items = Vec::new();
    add_items(
        &mut items,
        ArtifactKind::Property,
        baseline
            .security_state
            .property_results
            .keys()
            .chain(candidate.security_state.property_results.keys()),
        &impact.properties,
        impact.complete,
    );
    add_items(
        &mut items,
        ArtifactKind::Path,
        baseline
            .security_state
            .attack_paths
            .keys()
            .chain(candidate.security_state.attack_paths.keys()),
        &impact.paths,
        impact.complete,
    );
    add_items(
        &mut items,
        ArtifactKind::Vector,
        baseline
            .security_state
            .validation_results
            .keys()
            .chain(candidate.security_state.validation_results.keys()),
        &impact.vectors,
        impact.complete,
    );
    items.sort_by(|a, b| (a.kind, &a.id).cmp(&(b.kind, &b.id)));
    let mut plan = ContinuousRevalidationPlan {
        schema_version: "1".to_owned(),
        id: String::new(),
        baseline_state: baseline.security_state.id.clone(),
        candidate_state: candidate.security_state.id.clone(),
        change_set_digest,
        full_fallback: !impact.complete,
        items,
    };
    plan.id = format!("crp:{}", digest(&plan)?);
    Ok(plan)
}

fn add_items<'a>(
    output: &mut Vec<PlanItem>,
    kind: ArtifactKind,
    ids: impl Iterator<Item = &'a String>,
    affected: &BTreeSet<String>,
    complete: bool,
) {
    let unique: BTreeSet<_> = ids.cloned().collect();
    for id in unique {
        let (action, reason) = if !complete {
            (
                PlanAction::Unknown,
                "impact is unknown; full fallback required",
            )
        } else if affected.contains(&id) {
            (PlanAction::Revalidate, "security dependency changed")
        } else {
            (PlanAction::Reuse, "no mapped security dependency changed")
        };
        output.push(PlanItem {
            kind,
            id,
            action,
            reason: reason.to_owned(),
        });
    }
}
