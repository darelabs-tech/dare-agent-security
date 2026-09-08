//! The relationship graph.
//!
//! Edges are typed and closed. A relationship word appearing in an imported
//! document cannot invent a relation type: if the engine cannot map it onto one
//! of these thirteen, the edge is refused rather than stored as a string nobody
//! can reason about.
//!
//! Two rules do most of the work:
//!
//! - **A dangling endpoint is not an edge.** An edge naming a component that is
//!   not in the graph describes a relationship to something the engine cannot
//!   see, and reasoning over it would mean reasoning about an absence.
//! - **Declared and observed are different observations.** A dependency the
//!   manifest lists and never loads, and one loaded that nobody declared, are
//!   different findings with different fixes. Collapsing them into "the edges
//!   differ" loses which direction the difference goes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::canonical::assert_safe_identifier;
use crate::component::Component;
use crate::error::{Result, SupplyChainError};
use crate::limits;
use crate::source::{EvidenceSource, ObservationKind};

/// The closed relation set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelationType {
    DependsOn,
    Uses,
    Calls,
    Loads,
    ProvidedBy,
    BuiltFrom,
    TrainedFrom,
    FineTunedFrom,
    EmbedsWith,
    ExposesTool,
    ConnectsTo,
    AttestedBy,
    SignedBy,
}

impl RelationType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DependsOn => "DEPENDS_ON",
            Self::Uses => "USES",
            Self::Calls => "CALLS",
            Self::Loads => "LOADS",
            Self::ProvidedBy => "PROVIDED_BY",
            Self::BuiltFrom => "BUILT_FROM",
            Self::TrainedFrom => "TRAINED_FROM",
            Self::FineTunedFrom => "FINE_TUNED_FROM",
            Self::EmbedsWith => "EMBEDS_WITH",
            Self::ExposesTool => "EXPOSES_TOOL",
            Self::ConnectsTo => "CONNECTS_TO",
            Self::AttestedBy => "ATTESTED_BY",
            Self::SignedBy => "SIGNED_BY",
        }
    }

    pub fn all() -> [Self; 13] {
        [
            Self::DependsOn,
            Self::Uses,
            Self::Calls,
            Self::Loads,
            Self::ProvidedBy,
            Self::BuiltFrom,
            Self::TrainedFrom,
            Self::FineTunedFrom,
            Self::EmbedsWith,
            Self::ExposesTool,
            Self::ConnectsTo,
            Self::AttestedBy,
            Self::SignedBy,
        ]
    }

    /// Whether this relation expresses model lineage.
    ///
    /// The three the model-lineage invariant reads. `BUILT_FROM` is included
    /// because a model built from another model is lineage whatever the
    /// document called it.
    pub fn is_lineage(self) -> bool {
        matches!(
            self,
            Self::TrainedFrom | Self::FineTunedFrom | Self::BuiltFrom
        )
    }

    /// Whether this relation is a dependency in the sense the
    /// dependency-integrity invariant compares.
    pub fn is_dependency(self) -> bool {
        matches!(
            self,
            Self::DependsOn | Self::Uses | Self::Loads | Self::Calls
        )
    }
}

/// One typed edge.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relationship {
    pub source_id: String,
    pub target_id: String,
    pub relation: RelationType,
    /// Whether this edge was declared, observed, or both.
    pub observation: ObservationKind,
    pub evidence_source: EvidenceSource,
}

impl Relationship {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.source_id, "relationship source")?;
        assert_safe_identifier(&self.target_id, "relationship target")?;
        if self.source_id == self.target_id {
            // A component depending on itself is either a parsing artifact or a
            // cycle of length one. Neither is a relationship worth reasoning
            // about, and admitting it makes every depth walk unbounded.
            return Err(SupplyChainError::invalid(format!(
                "component `{}` relates to itself",
                self.source_id
            )));
        }
        Ok(())
    }

    /// A stable identity for this edge, independent of the order edges arrived.
    pub fn edge_key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.source_id,
            self.relation.as_str(),
            self.target_id
        )
    }
}

/// The normalized graph.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationshipGraph {
    /// Ordered, so two documents listing the same edges in different orders
    /// produce the same graph and the same digest.
    #[serde(default)]
    pub edges: BTreeSet<Relationship>,
}

impl RelationshipGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an edge, deduplicating identical ones.
    ///
    /// Two documents describing the same dependency is the normal case for a
    /// merged BOM, and reporting it as a duplicate would fire constantly.
    pub fn insert(&mut self, edge: Relationship) -> Result<()> {
        edge.validate()?;
        self.edges.insert(edge);
        Ok(())
    }

    /// Refuse a graph whose edges point at components it does not contain.
    ///
    /// An edge to an absent component describes a relationship to something the
    /// engine cannot see. Evaluating it would mean reasoning about an absence,
    /// and reporting a finding about it would name a component nobody can look
    /// up.
    pub fn assert_no_dangling(&self, components: &[Component]) -> Result<()> {
        let known: BTreeSet<&str> = components
            .iter()
            .map(|component| component.component_id.as_str())
            .collect();

        for edge in &self.edges {
            for (endpoint, role) in [(&edge.source_id, "source"), (&edge.target_id, "target")] {
                if !known.contains(endpoint.as_str()) {
                    return Err(SupplyChainError::invalid(format!(
                        "a {} relationship names a {role} component that is not in the graph",
                        edge.relation.as_str()
                    )));
                }
            }
        }
        Ok(())
    }

    /// Every edge of a given observation kind.
    pub fn by_observation(&self, kind: ObservationKind) -> BTreeSet<&Relationship> {
        self.edges
            .iter()
            .filter(|edge| edge.observation == kind)
            .collect()
    }

    /// Dependency edges keyed by their stable identity, ignoring how they were
    /// observed.
    fn dependency_keys(&self, kinds: &[ObservationKind]) -> BTreeSet<String> {
        self.edges
            .iter()
            .filter(|edge| edge.relation.is_dependency() && kinds.contains(&edge.observation))
            .map(Relationship::edge_key)
            .collect()
    }

    /// Dependency edges observed but never declared.
    ///
    /// An insertion: something is loaded that no approved manifest lists.
    pub fn undeclared_dependencies(&self) -> Vec<&Relationship> {
        let declared = self.dependency_keys(&[
            ObservationKind::Declared,
            ObservationKind::DeclaredAndObserved,
        ]);
        self.edges
            .iter()
            .filter(|edge| {
                edge.relation.is_dependency()
                    && edge.observation == ObservationKind::Observed
                    && !declared.contains(&edge.edge_key())
            })
            .collect()
    }

    /// Dependency edges declared but never observed.
    ///
    /// The other direction, and a different problem: a manifest describing a
    /// system that is not the system running.
    pub fn unobserved_dependencies(&self) -> Vec<&Relationship> {
        let observed = self.dependency_keys(&[
            ObservationKind::Observed,
            ObservationKind::DeclaredAndObserved,
        ]);
        self.edges
            .iter()
            .filter(|edge| {
                edge.relation.is_dependency()
                    && edge.observation == ObservationKind::Declared
                    && !observed.contains(&edge.edge_key())
            })
            .collect()
    }

    /// Whether both sides of the declared/observed comparison exist.
    ///
    /// Without both, the graph describes what was expected or what was seen,
    /// and the comparison has nothing to compare.
    pub fn is_comparable(&self) -> bool {
        let has_declared = self.edges.iter().any(|edge| {
            matches!(
                edge.observation,
                ObservationKind::Declared | ObservationKind::DeclaredAndObserved
            )
        });
        let has_observed = self.edges.iter().any(|edge| {
            matches!(
                edge.observation,
                ObservationKind::Observed | ObservationKind::DeclaredAndObserved
            )
        });
        has_declared && has_observed
    }

    /// Lineage edges out of one component.
    pub fn lineage_of<'a>(&'a self, component_id: &str) -> Vec<&'a Relationship> {
        self.edges
            .iter()
            .filter(|edge| edge.relation.is_lineage() && edge.source_id == component_id)
            .collect()
    }

    /// Refuse a graph deeper than the approved ceiling, or one that cycles.
    ///
    /// A cycle is refused rather than walked: a dependency cycle in a bill of
    /// materials is a description no build could have produced, and walking it
    /// is how a crafted document turns a bounded engine into a stalled one.
    pub fn assert_bounded_depth(&self) -> Result<()> {
        let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for edge in &self.edges {
            if edge.relation.is_dependency() {
                adjacency
                    .entry(edge.source_id.as_str())
                    .or_default()
                    .push(edge.target_id.as_str());
            }
        }

        for start in adjacency.keys() {
            let mut stack = vec![(*start, 0u32)];
            let mut on_path: BTreeSet<&str> = BTreeSet::new();
            while let Some((node, depth)) = stack.pop() {
                if depth > limits::HARD_MAX_DEPENDENCY_DEPTH {
                    return Err(SupplyChainError::BudgetExhausted(format!(
                        "a dependency path reached depth {depth}; the hard maximum is {}",
                        limits::HARD_MAX_DEPENDENCY_DEPTH
                    )));
                }
                if !on_path.insert(node) {
                    return Err(SupplyChainError::invalid(
                        "the dependency graph contains a cycle, which no build could have \
                         produced"
                            .to_owned(),
                    ));
                }
                for next in adjacency.get(node).into_iter().flatten() {
                    stack.push((next, depth + 1));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::component::tests::component;
    use crate::source::ComponentType;

    pub(crate) fn edge(
        source: &str,
        target: &str,
        relation: RelationType,
        observation: ObservationKind,
    ) -> Relationship {
        Relationship {
            source_id: source.to_owned(),
            target_id: target.to_owned(),
            relation,
            observation,
            evidence_source: EvidenceSource::CycloneDx,
        }
    }

    fn graph(edges: Vec<Relationship>) -> RelationshipGraph {
        let mut graph = RelationshipGraph::new();
        for edge in edges {
            graph.insert(edge).expect("valid edge");
        }
        graph
    }

    #[test]
    fn the_relation_set_is_closed_and_uniquely_named() {
        let names: BTreeSet<&str> = RelationType::all().iter().map(|r| r.as_str()).collect();
        assert_eq!(names.len(), 13);
    }

    #[test]
    fn an_imported_relationship_word_cannot_invent_a_relation_type() {
        // The reason this is an enum. A document that used its own vocabulary
        // must be refused, not stored as a string nobody can reason about.
        for hostile in [
            "\"VENDORS\"",
            "\"RELATES_TO\"",
            "\"OTHER\"",
            "\"depends_on\"",
        ] {
            assert!(
                serde_json::from_str::<RelationType>(hostile).is_err(),
                "`{hostile}` was admitted"
            );
        }
    }

    #[test]
    fn a_dangling_endpoint_is_refused() {
        // An edge to an absent component describes a relationship to something
        // the engine cannot see.
        let components = vec![component("app", ComponentType::Agent)];
        let graph = graph(vec![edge(
            "app",
            "missing",
            RelationType::DependsOn,
            ObservationKind::Observed,
        )]);
        let err = graph
            .assert_no_dangling(&components)
            .expect_err("must be refused");
        assert!(err.to_string().contains("target"));
    }

    #[test]
    fn a_complete_graph_passes_the_dangling_check() {
        let components = vec![
            component("app", ComponentType::Agent),
            component("react", ComponentType::Package),
        ];
        let graph = graph(vec![edge(
            "app",
            "react",
            RelationType::DependsOn,
            ObservationKind::DeclaredAndObserved,
        )]);
        graph.assert_no_dangling(&components).expect("no dangling");
    }

    #[test]
    fn a_self_edge_is_refused() {
        let mut graph = RelationshipGraph::new();
        assert!(graph
            .insert(edge(
                "app",
                "app",
                RelationType::DependsOn,
                ObservationKind::Observed
            ))
            .is_err());
    }

    #[test]
    fn an_undeclared_dependency_and_a_missing_one_are_different_findings() {
        // Collapsing them into "the edges differ" loses which direction the
        // difference goes, and the two have different fixes.
        let graph = graph(vec![
            edge(
                "app",
                "react",
                RelationType::DependsOn,
                ObservationKind::DeclaredAndObserved,
            ),
            edge(
                "app",
                "telemetry",
                RelationType::DependsOn,
                ObservationKind::Observed,
            ),
            edge(
                "app",
                "lodash",
                RelationType::DependsOn,
                ObservationKind::Declared,
            ),
        ]);

        let undeclared = graph.undeclared_dependencies();
        assert_eq!(undeclared.len(), 1);
        assert_eq!(undeclared[0].target_id, "telemetry");

        let unobserved = graph.unobserved_dependencies();
        assert_eq!(unobserved.len(), 1);
        assert_eq!(unobserved[0].target_id, "lodash");
    }

    #[test]
    fn an_agreeing_graph_reports_neither() {
        let graph = graph(vec![edge(
            "app",
            "react",
            RelationType::DependsOn,
            ObservationKind::DeclaredAndObserved,
        )]);
        assert!(graph.undeclared_dependencies().is_empty());
        assert!(graph.unobserved_dependencies().is_empty());
        assert!(graph.is_comparable());
    }

    #[test]
    fn a_graph_with_only_one_side_is_not_comparable() {
        // A graph of only observed edges describes what was seen. There is
        // nothing to compare it against, and the evaluator must say so rather
        // than report every edge as undeclared.
        let observed = graph(vec![edge(
            "app",
            "react",
            RelationType::DependsOn,
            ObservationKind::Observed,
        )]);
        assert!(!observed.is_comparable());

        let declared = graph(vec![edge(
            "app",
            "react",
            RelationType::DependsOn,
            ObservationKind::Declared,
        )]);
        assert!(!declared.is_comparable());
    }

    #[test]
    fn identical_edges_deduplicate_deterministically() {
        // Two documents describing the same dependency is the normal case for a
        // merged BOM. Reporting it would fire on every real document.
        let mut graph = RelationshipGraph::new();
        for _ in 0..3 {
            graph
                .insert(edge(
                    "app",
                    "react",
                    RelationType::DependsOn,
                    ObservationKind::DeclaredAndObserved,
                ))
                .expect("valid");
        }
        assert_eq!(graph.edges.len(), 1);
    }

    #[test]
    fn edge_order_does_not_change_the_graph() {
        let forward = graph(vec![
            edge(
                "app",
                "react",
                RelationType::DependsOn,
                ObservationKind::Observed,
            ),
            edge(
                "app",
                "vue",
                RelationType::DependsOn,
                ObservationKind::Observed,
            ),
        ]);
        let reverse = graph(vec![
            edge(
                "app",
                "vue",
                RelationType::DependsOn,
                ObservationKind::Observed,
            ),
            edge(
                "app",
                "react",
                RelationType::DependsOn,
                ObservationKind::Observed,
            ),
        ]);
        assert_eq!(forward, reverse);
        assert_eq!(
            crate::canonical::digest(&forward).unwrap(),
            crate::canonical::digest(&reverse).unwrap()
        );
    }

    #[test]
    fn only_dependency_relations_participate_in_the_declared_observed_comparison() {
        // An `ATTESTED_BY` edge observed and not declared is not a dependency
        // insertion, and reporting it as one would be a finding about the wrong
        // thing.
        let graph = graph(vec![edge(
            "react",
            "attestation-1",
            RelationType::AttestedBy,
            ObservationKind::Observed,
        )]);
        assert!(graph.undeclared_dependencies().is_empty());
    }

    #[test]
    fn a_dependency_cycle_is_refused_rather_than_walked() {
        // A cycle is a description no build could have produced, and walking it
        // is how a crafted document turns a bounded engine into a stalled one.
        let graph = graph(vec![
            edge("a", "b", RelationType::DependsOn, ObservationKind::Observed),
            edge("b", "c", RelationType::DependsOn, ObservationKind::Observed),
            edge("c", "a", RelationType::DependsOn, ObservationKind::Observed),
        ]);
        let err = graph.assert_bounded_depth().expect_err("must be refused");
        assert!(err.to_string().contains("cycle"));
    }

    #[test]
    fn a_deep_chain_is_refused_at_the_approved_ceiling() {
        let mut edges = Vec::new();
        for index in 0..(limits::HARD_MAX_DEPENDENCY_DEPTH + 5) {
            edges.push(edge(
                &format!("n{index}"),
                &format!("n{}", index + 1),
                RelationType::DependsOn,
                ObservationKind::Observed,
            ));
        }
        assert!(graph(edges).assert_bounded_depth().is_err());
    }

    #[test]
    fn an_ordinary_chain_stays_within_bounds() {
        let mut edges = Vec::new();
        for index in 0..10 {
            edges.push(edge(
                &format!("n{index}"),
                &format!("n{}", index + 1),
                RelationType::DependsOn,
                ObservationKind::Observed,
            ));
        }
        graph(edges).assert_bounded_depth().expect("within bounds");
    }

    #[test]
    fn lineage_relations_are_the_three_the_model_invariant_reads() {
        assert!(RelationType::TrainedFrom.is_lineage());
        assert!(RelationType::FineTunedFrom.is_lineage());
        assert!(RelationType::BuiltFrom.is_lineage());
        assert!(!RelationType::DependsOn.is_lineage());
        assert!(!RelationType::ProvidedBy.is_lineage());

        let graph = graph(vec![
            edge(
                "model",
                "base",
                RelationType::FineTunedFrom,
                ObservationKind::Observed,
            ),
            edge(
                "model",
                "react",
                RelationType::DependsOn,
                ObservationKind::Observed,
            ),
        ]);
        let lineage = graph.lineage_of("model");
        assert_eq!(lineage.len(), 1);
        assert_eq!(lineage[0].target_id, "base");
    }
}
