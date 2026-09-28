//! End to end (BLUEPRINT §5.2, tasks 031 and 035).
use std::path::{Path, PathBuf};

use dare_attack_graph::{
    model::{GraphEngine, SchemaRef},
    v2::{
        graph_id_v2, validate_graph_v2, validate_paths_v2, validate_projection_report, AliasReport,
        ArtifactReport, ArtifactSource, AttackGraphV2, AttackPathsDoc, FactCounts,
        ProjectionReport, SourcesV2, DOCUMENT_SCHEMA_VERSION, GRAPH_SCHEMA_ID_V2,
        GRAPH_SCHEMA_VERSION_V2, REPORT_SCHEMA_ID_V2,
    },
};

use crate::{
    bundle::load_bundle,
    designate,
    error::{AttackPathError, Refusal, Result},
    facts::{Designation, RunFacts},
    ids::sha256_prefixed,
    limits::{ConstructOptions, MAX_ARTIFACT_DIRS},
    merge::{merge, Merged},
    model::{load_model, AdmittedModel},
    paths,
    project::project,
};

/// Everything `validate attack-paths` writes, validated.
#[derive(Debug, Clone)]
pub struct Construction {
    pub graph: AttackGraphV2,
    pub paths: AttackPathsDoc,
    pub report: ProjectionReport,
}

fn internal(message: &'static str) -> AttackPathError {
    AttackPathError::Internal(message)
}

/// Loads and projects every artifact directory, refusing duplicates.
pub fn project_all(dirs: &[PathBuf]) -> Result<Vec<RunFacts>> {
    if dirs.is_empty() {
        return Err(Refusal::NoArtifacts.into());
    }
    if dirs.len() > MAX_ARTIFACT_DIRS {
        return Err(Refusal::TooManyArtifacts { given: dirs.len() }.into());
    }
    // Refusals name the position the user gave; the graph does not depend on
    // it. After loading, bundles are re-indexed in result-digest order so the
    // same artifacts in any order give byte-identical output (O-06).
    let mut bundles = Vec::with_capacity(dirs.len());
    for (index, dir) in dirs.iter().enumerate() {
        let bundle = load_bundle(index, dir)?;
        if let Some(first) = bundles
            .iter()
            .position(|b: &crate::bundle::LoadedBundle| b.result_digest == bundle.result_digest)
        {
            return Err(Refusal::DuplicateRun {
                first,
                second: index,
            }
            .into());
        }
        bundles.push(bundle);
    }
    bundles.sort_by(|a, b| a.result_digest.cmp(&b.result_digest));
    let mut runs = Vec::with_capacity(bundles.len());
    for (index, mut bundle) in bundles.into_iter().enumerate() {
        bundle.index = index;
        runs.push(project(&bundle)?);
    }
    Ok(runs)
}

fn engine() -> GraphEngine {
    GraphEngine {
        name: "dare-attack-path".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        commit: option_env!("DARE_BUILD_COMMIT")
            .unwrap_or("unrecorded")
            .into(),
    }
}

/// Builds the v2 graph and its projection report from run facts.
pub fn build_graph(
    runs: &[RunFacts],
    model: Option<&AdmittedModel>,
) -> Result<(AttackGraphV2, ProjectionReport)> {
    let mut merged: Merged = merge(runs, model)?;
    designate::apply_defaults(&mut merged);
    if let Some(model) = model {
        designate::apply_model(&mut merged, model)?;
    }
    let (target_id, target_version) = match model {
        Some(m) => (m.model.target_id.clone(), m.model.target_version.clone()),
        None => {
            let mut digests: Vec<&str> = runs.iter().map(|r| r.result_digest.as_str()).collect();
            digests.sort();
            let joined = digests.join("\n");
            let digest = sha256_prefixed(joined.as_bytes());
            ("unmodelled".to_owned(), digest[7..19].to_owned())
        }
    };
    let artifacts: Vec<ArtifactSource> = runs
        .iter()
        .map(|r| ArtifactSource {
            index: r.artifact_index,
            engine: r.engine.as_str().to_owned(),
            run: r.run.as_str().to_owned(),
            mode: r.mode.clone(),
            synthetic: r.synthetic,
            dynamic_authorized: r.dynamic_authorized,
            result_digest: r.result_digest.clone(),
            evidence_digest: r.evidence_digest.clone(),
            input_digests: r.input_digests.clone(),
        })
        .collect();
    let mut nodes: Vec<_> = merged.nodes.into_values().collect();
    for node in &mut nodes {
        node.provenance.sort();
        node.provenance.dedup();
    }
    let mut edges: Vec<_> = merged.edges.into_values().collect();
    for edge in &mut edges {
        edge.provenance.sort();
        edge.provenance.dedup();
    }
    let mut graph = AttackGraphV2 {
        schema: SchemaRef {
            id: GRAPH_SCHEMA_ID_V2.into(),
            version: GRAPH_SCHEMA_VERSION_V2.into(),
        },
        id: String::new(),
        target_id,
        target_version,
        sources: SourcesV2 {
            model_digest: model.map(|m| m.digest.clone()),
            artifacts,
        },
        engine: engine(),
        nodes,
        edges,
        entry_points: merged.entries.into_iter().collect(),
        targets: merged.targets.into_iter().collect(),
    };
    graph.id = graph_id_v2(&graph).map_err(|_| internal("graph id"))?;
    validate_graph_v2(&graph).map_err(|_| internal("constructed graph failed v2 validation"))?;

    let report = ProjectionReport {
        schema_id: REPORT_SCHEMA_ID_V2.into(),
        schema_version: DOCUMENT_SCHEMA_VERSION.into(),
        graph_id: graph.id.clone(),
        model_digest: graph.sources.model_digest.clone(),
        artifacts: runs
            .iter()
            .map(|r| ArtifactReport {
                index: r.artifact_index,
                engine: r.engine.as_str().to_owned(),
                run: r.run.as_str().to_owned(),
                mode: r.mode.clone(),
                synthetic: r.synthetic,
                dynamic_authorized: r.dynamic_authorized,
                result_digest: r.result_digest.clone(),
                evidence_digest: r.evidence_digest.clone(),
                verified_inputs: r.verified_inputs.clone(),
                facts: FactCounts {
                    nodes: r.nodes.len() as u32,
                    edges: r.edges.len() as u32,
                    guards: r.edges.iter().map(|e| e.guards.len() as u32).sum(),
                    entries: r
                        .designations
                        .iter()
                        .filter(|d| matches!(d.designation, Designation::Entry(_)))
                        .count() as u32,
                    targets: r
                        .designations
                        .iter()
                        .filter(|d| matches!(d.designation, Designation::Target(_)))
                        .count() as u32,
                },
                unprojected: r.unprojected.clone(),
            })
            .collect(),
        aliases_used: aliases(model, &merged.alias_hits, true),
        aliases_unused: aliases(model, &merged.alias_hits, false),
    };
    validate_projection_report(&graph, &report)
        .map_err(|_| internal("projection report failed v2 validation"))?;
    Ok((graph, report))
}

fn aliases(
    model: Option<&AdmittedModel>,
    hits: &std::collections::BTreeMap<usize, u32>,
    used: bool,
) -> Vec<AliasReport> {
    let Some(model) = model else { return vec![] };
    let mut out: Vec<AliasReport> = model
        .model
        .aliases
        .iter()
        .enumerate()
        .filter(|(index, _)| hits.contains_key(index) == used)
        .map(|(index, alias)| AliasReport {
            engine: alias.engine.as_str().to_owned(),
            local_id: alias.local_id.clone(),
            run: alias.run.clone(),
            entity_id: alias.entity_id.clone(),
            matched_nodes: hits.get(&index).copied().unwrap_or(0),
        })
        .collect();
    out.sort();
    out
}

/// The whole construction: load, project, merge, designate, enumerate,
/// classify, validate.
pub fn construct(
    dirs: &[PathBuf],
    model_path: Option<&Path>,
    options: &ConstructOptions,
) -> Result<Construction> {
    options.validate()?;
    let model = model_path.map(load_model).transpose()?;
    let runs = project_all(dirs)?;
    let (graph, report) = build_graph(&runs, model.as_ref())?;
    let paths = paths::attack_paths(&graph, options)?;
    validate_paths_v2(&graph, &paths)
        .map_err(|_| internal("constructed paths failed v2 validation"))?;
    Ok(Construction {
        graph,
        paths,
        report,
    })
}
