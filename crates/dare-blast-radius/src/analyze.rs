//! End to end (BLUEPRINT §5.2): admit, validate, resolve, search, classify,
//! count, validate the document. Nothing is written.
use std::path::Path;

use dare_attack_graph::v2::{validate_graph_v2, AttackGraphV2, ATTACK_GRAPH_SCHEMA_V2_JSON};
use serde_json::Value;

use crate::{
    admit::read_admitted,
    classify::classify,
    delta::remediation_delta,
    error::{BlastError, Refusal, Result},
    impact::{frontier, totals, view_impact},
    limits::{
        check, Bounds, MAX_DELTA_EDGES, MAX_DEPTH, MAX_FILE_BYTES, MAX_STATES_PER_SEARCH,
        MAX_STATES_TOTAL,
    },
    model::{
        BlastRadiusDoc, DocBounds, SeedReport, StopBound, BLAST_RADIUS_SCHEMA_ID,
        BLAST_RADIUS_SCHEMA_VERSION,
    },
    reach::{initial_authority, search, Indexed, View},
    scenario::{self, ResolvedSeed},
    validate::validate_blast_radius,
};

/// Where the seeds come from.
#[derive(Debug, Clone, Copy)]
pub enum Seeding<'a> {
    Scenario(&'a Path),
    EntryPoints,
}

/// Caller bounds. `None` keeps the default; a value may only lower it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    pub max_depth: Option<u32>,
    pub max_states: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Analysis {
    pub doc: BlastRadiusDoc,
    pub graph: AttackGraphV2,
}

/// Admits and validates a v2 graph file. Any failure is `InvalidGraph`, and
/// the message never echoes the file.
pub fn load_graph(path: &Path) -> Result<AttackGraphV2> {
    let value = read_admitted(path, "graph", MAX_FILE_BYTES)?;
    graph_from_value(value)
}

pub fn graph_from_value(value: Value) -> Result<AttackGraphV2> {
    let schema: Value = serde_json::from_str(ATTACK_GRAPH_SCHEMA_V2_JSON)
        .map_err(|_| BlastError::Internal("embedded graph schema"))?;
    let validator = jsonschema::options()
        .build(&schema)
        .map_err(|_| BlastError::Internal("embedded graph schema"))?;
    if validator.iter_errors(&value).next().is_some() {
        return Err(Refusal::InvalidGraph.into());
    }
    let graph: AttackGraphV2 = serde_json::from_value(value).map_err(|_| Refusal::InvalidGraph)?;
    validate_graph_v2(&graph).map_err(|_| Refusal::InvalidGraph)?;
    Ok(graph)
}

pub fn analyze(graph: &Path, seeding: Seeding<'_>, options: &Options) -> Result<Analysis> {
    check_options(options)?;
    let graph = load_graph(graph)?;
    let seeds = match seeding {
        Seeding::Scenario(path) => scenario::load_scenario(path, &graph)?,
        Seeding::EntryPoints => scenario::entry_point_seeds(&graph)?,
    };
    let doc = analyze_graph(&graph, &seeds, options)?;
    Ok(Analysis { doc, graph })
}

fn check_options(options: &Options) -> Result<()> {
    if let Some(depth) = options.max_depth {
        check("max_depth", u64::from(depth), u64::from(MAX_DEPTH))?;
    }
    if let Some(states) = options.max_states {
        check("max_states", states, MAX_STATES_PER_SEARCH)?;
    }
    Ok(())
}

/// The analysis over an admitted graph and resolved seeds.
pub fn analyze_graph(
    graph: &AttackGraphV2,
    seeding: &scenario::Seeding,
    options: &Options,
) -> Result<BlastRadiusDoc> {
    check_options(options)?;
    let bounds = Bounds::default()
        .lower(options.max_depth, options.max_states)
        .lower(seeding.max_depth, seeding.max_states);
    bounds.validate()?;
    let index = Indexed::new(graph);
    let mut seeds: Vec<ResolvedSeed> = seeding.seeds.clone();
    seeds.sort();
    seeds.dedup();
    let mut budget = MAX_STATES_TOTAL;
    let mut reports = Vec::with_capacity(seeds.len());
    for seed in &seeds {
        let run = |view, budget: &mut u64| {
            search(
                &index,
                &seed.node,
                initial_authority(seed.kind, &seed.node),
                view,
                bounds,
                budget,
                None,
            )
        };
        let structural = run(View::Structural, &mut budget);
        let uncontained = run(View::Uncontained, &mut budget);
        let targets = classify(&index, seed, &structural, &uncontained);
        let impact = view_impact(&index, seed, &structural, &uncontained, &targets);
        reports.push(SeedReport {
            node: seed.node.clone(),
            kind: seed.kind,
            tenant: seed.tenant.clone(),
            structural: structural.report,
            uncontained: uncontained.report,
            targets,
            impact,
        });
    }
    let search_truncated = reports
        .iter()
        .any(|r| r.structural.truncated || r.uncontained.truncated);
    let mut stopped_by: Vec<StopBound> = reports
        .iter()
        .flat_map(|r| [r.structural.stopped_by, r.uncontained.stopped_by])
        .flatten()
        .collect();
    let pairs: Vec<(ResolvedSeed, &SeedReport)> =
        seeds.iter().cloned().zip(reports.iter()).collect();
    let remediation_delta = remediation_delta(&index, &pairs, bounds, &mut budget);
    // A budget the delta ran out of truncates the run as well (REGRESSION R-4).
    let delta_budget = budget == 0 && remediation_delta.iter().any(|d| d.partial);
    if delta_budget {
        stopped_by.push(StopBound::MaxStatesTotal);
    }
    stopped_by.sort();
    stopped_by.dedup();
    let doc = BlastRadiusDoc {
        schema_id: BLAST_RADIUS_SCHEMA_ID.into(),
        schema_version: BLAST_RADIUS_SCHEMA_VERSION.into(),
        graph_id: graph.id.clone(),
        scenario_id: seeding.scenario_id.clone(),
        scenario_digest: seeding.scenario_digest.clone(),
        bounds: DocBounds {
            max_depth: bounds.max_depth,
            max_states: bounds.max_states,
            max_states_total: MAX_STATES_TOTAL,
            max_delta_edges: MAX_DELTA_EDGES as u32,
        },
        totals: totals(&reports),
        frontier: frontier(&index, &reports),
        seeds_skipped: seeding.skipped,
        seeds_omitted: seeding.omitted,
        seeds: reports,
        remediation_delta,
        truncated: search_truncated || delta_budget,
        stopped_by,
    };
    validate_blast_radius(graph, &doc)?;
    Ok(doc)
}
