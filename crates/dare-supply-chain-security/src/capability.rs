//! Capability drift for externally supplied components.
//!
//! This module supplies evidence to `AGENT.SUPPLY_CHAIN.CAPABILITY_DRIFT`,
//! which Cycle 012 created. It does **not** create a second drift property.
//! Two properties both meaning "capabilities changed" would eventually disagree
//! about what drift is, and a report would have to explain which one the reader
//! was looking at.
//!
//! # What drift is, and what it is not
//!
//! Drift is a component doing *more* than it was approved to do. A tool that
//! gained `write-file` since approval is a finding; one that lost `read-file`
//! is not — a component doing less has not crossed a boundary, and reporting it
//! would train an operator to skim past drift findings.
//!
//! Both sides are required. An approved set alone describes what was permitted;
//! an observed set alone describes what exists. Drift is the difference, and
//! with one side missing there is no difference to take.
//!
//! # The boundary with Cycle 014
//!
//! Whether a tool is *allowed to use* a capability at runtime is Cycle 014's
//! question. This cycle asks only whether the capability set changed from what
//! a supply-chain approval recorded. A component may drift and still be
//! correctly authorized, and may be correctly authorized and still have
//! drifted; the two are independent and are answered by different engines.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::component::{CapabilityProjection, CapabilityRef, Component};
use crate::manifest::DareManifest;

/// What the evidence says about one component's capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftAssessment {
    pub component_id: String,
    /// Capabilities observed that were never approved.
    pub introduced: Vec<String>,
    /// Capabilities approved that are no longer observed. Recorded, never a
    /// violation.
    pub withdrawn: Vec<String>,
    /// Whether both sides were available.
    pub comparable: bool,
}

impl DriftAssessment {
    /// Whether drift was observed.
    ///
    /// `None` when the comparison could not be made — distinct from `Some(false)`,
    /// which means it was made and nothing had changed.
    pub fn drifted(&self) -> Option<bool> {
        self.comparable.then_some(!self.introduced.is_empty())
    }
}

/// Assess one component's capability drift.
///
/// The approved side comes from the manifest where it names one, falling back
/// to the component's own projection. The manifest wins deliberately: a
/// component describing its own approved capabilities would be approving
/// itself, and the fallback exists only for evidence bundles that carry a
/// projection with no manifest beside it.
pub fn assess(component: &Component, manifest: &DareManifest) -> DriftAssessment {
    let observed: BTreeSet<String> = component
        .capabilities
        .as_ref()
        .map(|projection| {
            projection
                .observed
                .iter()
                .map(|capability| capability.capability_id.clone())
                .collect()
        })
        .unwrap_or_default();

    let approved: BTreeSet<String> = manifest
        .approved_capabilities
        .get(&component.component_id)
        .cloned()
        .unwrap_or_else(|| {
            component
                .capabilities
                .as_ref()
                .map(|projection| {
                    projection
                        .approved
                        .iter()
                        .map(|capability| capability.capability_id.clone())
                        .collect()
                })
                .unwrap_or_default()
        });

    let comparable = !approved.is_empty() && !observed.is_empty();

    DriftAssessment {
        component_id: component.component_id.clone(),
        introduced: observed.difference(&approved).cloned().collect(),
        withdrawn: approved.difference(&observed).cloned().collect(),
        comparable,
    }
}

/// Build a projection from two capability id sets.
///
/// A convenience for fixtures and adapters; the model itself stores
/// [`CapabilityRef`] so a capability can carry a kind.
pub fn projection(approved: &[&str], observed: &[&str]) -> CapabilityProjection {
    CapabilityProjection {
        approved: approved
            .iter()
            .map(|id| CapabilityRef {
                capability_id: (*id).to_owned(),
                kind: None,
            })
            .collect(),
        observed: observed
            .iter()
            .map(|id| CapabilityRef {
                capability_id: (*id).to_owned(),
                kind: None,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::tests::component;
    use crate::source::ComponentType;
    use std::collections::{BTreeMap, BTreeSet};

    fn tool(projection_value: Option<CapabilityProjection>) -> Component {
        let mut tool = component("file-tool", ComponentType::Tool);
        tool.capabilities = projection_value;
        tool
    }

    #[test]
    fn an_unchanged_capability_set_has_not_drifted() {
        let component = tool(Some(projection(&["read-file"], &["read-file"])));
        let assessment = assess(&component, &DareManifest::default());
        assert!(assessment.comparable);
        assert_eq!(assessment.drifted(), Some(false));
        assert!(assessment.introduced.is_empty());
    }

    #[test]
    fn an_introduced_capability_is_drift_and_is_named() {
        // "This tool drifted" is not actionable. "This tool gained write-file"
        // is.
        let component = tool(Some(projection(
            &["read-file"],
            &["read-file", "write-file"],
        )));
        let assessment = assess(&component, &DareManifest::default());
        assert_eq!(assessment.drifted(), Some(true));
        assert_eq!(assessment.introduced, vec!["write-file"]);
    }

    #[test]
    fn a_withdrawn_capability_is_recorded_and_is_not_drift() {
        // A component doing less than it was approved to do has not crossed a
        // boundary, and reporting it would train an operator to skim past drift
        // findings.
        let component = tool(Some(projection(
            &["read-file", "write-file"],
            &["read-file"],
        )));
        let assessment = assess(&component, &DareManifest::default());
        assert_eq!(assessment.drifted(), Some(false));
        assert_eq!(assessment.withdrawn, vec!["write-file"]);
    }

    #[test]
    fn one_side_alone_is_not_comparable() {
        // An approved set describes what was permitted; an observed set
        // describes what exists. Drift is the difference, and with one side
        // missing there is no difference to take.
        for (approved, observed) in [
            (vec!["read-file"], Vec::new()),
            (Vec::new(), vec!["read-file"]),
        ] {
            let component = tool(Some(projection(&approved, &observed)));
            let assessment = assess(&component, &DareManifest::default());
            assert!(!assessment.comparable);
            assert_eq!(
                assessment.drifted(),
                None,
                "a one-sided projection was treated as a comparison"
            );
        }
    }

    #[test]
    fn no_projection_at_all_is_also_not_comparable() {
        let assessment = assess(&tool(None), &DareManifest::default());
        assert!(!assessment.comparable);
        assert_eq!(assessment.drifted(), None);
    }

    #[test]
    fn the_manifest_wins_over_the_components_own_approved_set() {
        // A component describing its own approved capabilities would be
        // approving itself. The fallback exists only for bundles that carry a
        // projection with no manifest beside it.
        let component = tool(Some(projection(
            &["read-file", "write-file"],
            &["read-file", "write-file"],
        )));
        let manifest = DareManifest {
            schema_version: "1".to_owned(),
            approved_capabilities: BTreeMap::from([(
                "file-tool".to_owned(),
                BTreeSet::from(["read-file".to_owned()]),
            )]),
            ..Default::default()
        };

        let assessment = assess(&component, &manifest);
        assert_eq!(
            assessment.drifted(),
            Some(true),
            "the component approved itself"
        );
        assert_eq!(assessment.introduced, vec!["write-file"]);
    }

    #[test]
    fn drift_is_reported_for_any_component_class_that_carries_capabilities() {
        // MCP servers and skill plugins drift the same way tools do, and an
        // engine that only looked at TOOL would miss the surfaces most likely
        // to gain one.
        for class in [
            ComponentType::Tool,
            ComponentType::McpServer,
            ComponentType::SkillPlugin,
            ComponentType::Guardrail,
        ] {
            let mut component = component("thing", class);
            component.capabilities = Some(projection(&["a"], &["a", "b"]));
            assert_eq!(
                assess(&component, &DareManifest::default()).drifted(),
                Some(true),
                "{class:?} drift was not reported"
            );
        }
    }

    #[test]
    fn the_assessment_says_nothing_about_runtime_authorization() {
        // Cycle 014's question. A component may drift and still be correctly
        // authorized, and may be correctly authorized and still have drifted.
        let rendered = serde_json::to_string(&assess(
            &tool(Some(projection(&["a"], &["a", "b"]))),
            &DareManifest::default(),
        ))
        .expect("serializes");
        for absent in ["authorized", "permitted", "allowed", "denied"] {
            assert!(
                !rendered.to_lowercase().contains(absent),
                "the drift assessment claims something about runtime authorization"
            );
        }
    }
}
