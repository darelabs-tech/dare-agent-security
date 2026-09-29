//! Document invariants (task-016, BLUEPRINT §4.5): one doctored document per
//! invariant, each refused as an internal error.
mod support;

use dare_attack_graph::v2::{ControlState, TargetClass};
use dare_blast_radius::{
    analyze::{analyze_graph, Options},
    model::{BlastRadiusDoc, Exposure, StopBound},
    scenario::entry_point_seeds,
    validate_blast_radius, BlastError,
};
use support::lab::{lab, Lab};

fn produced() -> (Lab, BlastRadiusDoc) {
    let l = lab();
    let seeds = entry_point_seeds(&l.graph).unwrap();
    let doc = analyze_graph(&l.graph, &seeds, &Options::default()).unwrap();
    (l, doc)
}

fn refused(l: &Lab, doc: &BlastRadiusDoc, invariant: &str) {
    match validate_blast_radius(&l.graph, doc) {
        Err(BlastError::Internal(why)) => {
            assert!(why.starts_with(invariant), "{why} is not {invariant}")
        }
        other => panic!("{invariant} not refused: {other:?}"),
    }
}

fn exposed_target(doc: &mut BlastRadiusDoc) -> &mut dare_blast_radius::model::TargetReach {
    doc.seeds
        .iter_mut()
        .flat_map(|s| s.targets.iter_mut())
        .find(|t| t.exposure == Exposure::Exposed && t.structural_route.edges.len() >= 2)
        .unwrap()
}

#[test]
fn a_document_the_engine_produces_passes() {
    let (l, doc) = produced();
    validate_blast_radius(&l.graph, &doc).unwrap();
    // The lab covers every part of the document.
    assert_eq!(doc.seeds.len(), 2);
    assert!(doc.totals.exposed > 0 && doc.totals.contained > 0);
    assert!(!doc.frontier.is_empty() && !doc.remediation_delta.is_empty());
}

#[test]
fn invariant_1_graph_and_schema() {
    let (l, doc) = produced();
    let mut d = doc.clone();
    d.graph_id = format!("graph:{}", "0".repeat(64));
    refused(&l, &d, "invariant 1");
    let mut d = doc.clone();
    d.schema_version = "2.0.0".into();
    refused(&l, &d, "invariant 1");
    let mut d = doc;
    d.bounds.max_depth = 13;
    refused(&l, &d, "invariant 1");
}

#[test]
fn invariant_2_routes_are_walks_of_known_ids_from_the_seed() {
    let (l, doc) = produced();
    let mut d = doc.clone();
    exposed_target(&mut d).structural_route.edges[0] = "edge:unknown".into();
    refused(&l, &d, "invariant 2");
    let mut d = doc.clone();
    exposed_target(&mut d).structural_route.edges.swap(0, 1);
    refused(&l, &d, "invariant 2");
    let mut d = doc.clone();
    exposed_target(&mut d).structural_route.nodes[0] = l.vault.clone();
    refused(&l, &d, "invariant 2");
    let mut d = doc;
    d.seeds[0].node = "node:human:nobody".into();
    refused(&l, &d, "invariant 2");
}

#[test]
fn invariant_3_every_step_is_explained() {
    let (l, mut doc) = produced();
    let seed = doc.seeds.iter_mut().find(|s| s.node == l.user).unwrap();
    let ledger = seed
        .targets
        .iter_mut()
        .find(|t| t.node == l.ledger)
        .unwrap();
    // A real walk, but its last access runs under a principal the user never
    // acquired.
    let route = &mut ledger.structural_route;
    route.nodes = vec![l.user.clone(), l.agent.clone(), l.ledger.clone()];
    let first = route.edges[0].clone();
    route.edges = vec![first, l.foreign.clone()];
    refused(&l, &doc, "invariant 3");
}

#[test]
fn invariant_4_control_fields_are_recomputed() {
    let (l, doc) = produced();
    let mut d = doc.clone();
    exposed_target(&mut d).structural_route.control_state = ControlState::ControlsHeld;
    refused(&l, &d, "invariant 4");
    let mut d = doc;
    exposed_target(&mut d)
        .structural_route
        .undecided_edges
        .clear();
    exposed_target(&mut d)
        .structural_route
        .failed_guards
        .clear();
    refused(&l, &d, "invariant 4");
}

#[test]
fn invariant_5_an_uncontained_route_crosses_no_held_edge() {
    let (l, mut doc) = produced();
    let seed = doc.seeds.iter_mut().find(|s| s.node == l.user).unwrap();
    let ledger = seed
        .targets
        .iter_mut()
        .find(|t| t.node == l.ledger)
        .unwrap();
    // Claim the held route as open, with consistent control fields.
    ledger.exposure = Exposure::Exposed;
    ledger.uncontained_route = Some(ledger.structural_route.clone());
    ledger.frontier.clear();
    refused(&l, &doc, "invariant 5");
}

#[test]
fn invariant_6_exposure_matches_the_routes_and_truncation() {
    let (l, doc) = produced();
    let mut d = doc.clone();
    exposed_target(&mut d).uncontained_route = None;
    refused(&l, &d, "invariant 6");
    let mut d = doc.clone();
    let seed = d.seeds.iter_mut().find(|s| s.node == l.user).unwrap();
    seed.targets
        .iter_mut()
        .find(|t| t.node == l.ledger)
        .unwrap()
        .exposure = Exposure::ContainmentUnknown;
    refused(&l, &d, "invariant 6");
    // CONTAINED under a truncated uncontained search.
    let mut d = doc;
    let seed = d.seeds.iter_mut().find(|s| s.node == l.user).unwrap();
    seed.uncontained.truncated = true;
    seed.uncontained.stopped_by = Some(StopBound::MaxStates);
    refused(&l, &d, "invariant 6");
}

#[test]
fn invariant_7_the_frontier_is_the_held_edges_of_the_structural_route() {
    let (l, doc) = produced();
    let mut d = doc.clone();
    let seed = d.seeds.iter_mut().find(|s| s.node == l.user).unwrap();
    let ledger = seed
        .targets
        .iter_mut()
        .find(|t| t.node == l.ledger)
        .unwrap();
    ledger.frontier = vec![l.fail_a.clone()];
    refused(&l, &d, "invariant 7");
    let mut d = doc;
    exposed_target(&mut d).frontier = vec![l.held.clone()];
    refused(&l, &d, "invariant 7");
}

#[test]
fn invariant_8_counts_are_recomputed() {
    let (l, doc) = produced();
    let mut d = doc.clone();
    d.totals.exposed += 1;
    refused(&l, &d, "invariant 8");
    let mut d = doc.clone();
    d.frontier[0].contained_targets += 1;
    refused(&l, &d, "invariant 8");
    let mut d = doc.clone();
    d.truncated = true;
    refused(&l, &d, "invariant 8");
    let mut d = doc.clone();
    d.seeds[0]
        .impact
        .structural
        .targets_by_class
        .insert(TargetClass::ExternalPublication, 1);
    refused(&l, &d, "invariant 8");
    let mut d = doc.clone();
    let user = d.seeds.iter_mut().find(|s| s.node == l.user).unwrap();
    user.impact.uncontained.trust_boundaries_crossed.clear();
    refused(&l, &d, "invariant 8");
    let mut d = doc.clone();
    let user = d.seeds.iter_mut().find(|s| s.node == l.user).unwrap();
    user.impact
        .structural
        .privileged_credentials_acquired
        .clear();
    refused(&l, &d, "invariant 8");
    let mut d = doc.clone();
    let user = d.seeds.iter_mut().find(|s| s.node == l.user).unwrap();
    user.impact.structural.tenants_reached = vec!["a".into(), "b".into()];
    refused(&l, &d, "invariant 8");
    let mut d = doc;
    d.remediation_delta[0].edge = l.held.clone();
    refused(&l, &d, "invariant 8");
}

#[test]
fn invariant_9_lists_are_sorted_and_unique() {
    let (l, doc) = produced();
    let mut d = doc.clone();
    d.seeds.reverse();
    refused(&l, &d, "invariant 9");
    let mut d = doc.clone();
    let user = d.seeds.iter_mut().find(|s| s.node == l.user).unwrap();
    user.targets.reverse();
    refused(&l, &d, "invariant 9");
    let mut d = doc.clone();
    assert!(d.remediation_delta.len() > 1);
    d.remediation_delta.reverse();
    refused(&l, &d, "invariant 9");
    let mut d = doc;
    let user = d.seeds.iter_mut().find(|s| s.node == l.user).unwrap();
    user.impact.structural.tenants_reached.push("b".into());
    refused(&l, &d, "invariant 9");
}
