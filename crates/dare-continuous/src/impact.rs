use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    changeset::{ChangeType, SecurityChangeSet},
    dependencies::DependencyMap,
    snapshot::SecurityStateSnapshot,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactResolution {
    pub complete: bool,
    pub properties: BTreeSet<String>,
    pub paths: BTreeSet<String>,
    pub vectors: BTreeSet<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ImpactResolver {
    dependencies: DependencyMap,
}

impl ImpactResolver {
    pub fn resolve(
        &self,
        changes: &SecurityChangeSet,
        candidate: &SecurityStateSnapshot,
    ) -> ImpactResolution {
        let mut result = ImpactResolution {
            complete: true,
            properties: BTreeSet::new(),
            paths: BTreeSet::new(),
            vectors: BTreeSet::new(),
            reasons: Vec::new(),
        };
        for change in &changes.changes {
            if change.change_type == ChangeType::Unknown {
                result.complete = false;
                result
                    .reasons
                    .push(format!("unknown impact for {}", change.entity));
                continue;
            }
            match self.dependencies.properties_for(change.change_type) {
                Some(properties) => result.properties.extend(properties.iter().cloned()),
                None => {
                    result.complete = false;
                    result.reasons.push(format!(
                        "no dependency mapping for {:?}",
                        change.change_type
                    ));
                }
            }
        }

        for (id, path) in &candidate.security_state.attack_paths {
            if path
                .property_ids
                .iter()
                .any(|property| result.properties.contains(property))
                || changes
                    .changes
                    .iter()
                    .any(|change| change.change_type == ChangeType::GraphChanged)
            {
                result.paths.insert(id.clone());
            }
        }
        for (id, validation) in &candidate.security_state.validation_results {
            if result.properties.contains(&validation.property_id)
                || validation
                    .path_id
                    .as_ref()
                    .is_some_and(|path| result.paths.contains(path))
                || changes
                    .changes
                    .iter()
                    .any(|change| change.change_type == ChangeType::ValidationChanged)
            {
                result.vectors.insert(id.clone());
            }
        }
        result.reasons.sort();
        result.reasons.dedup();
        result
    }
}
