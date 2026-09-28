//! Regenerates the STATIC-mode input documents under
//! `tests/fixtures/static-inputs/` from the engines' own built-in corpora.
//!
//! Run with `cargo test -p dare-attack-path --test generate_static_inputs --
//! --ignored`. The documents are the typed values the engines themselves use,
//! serialized in the exact form their `StaticAdapter` parses; the result and
//! evidence files are then produced by the real CLI in static mode (see
//! `tests/fixtures/static-inputs/README.md`). The non-ignored test checks the
//! committed files still equal what this generator writes.
use std::{fs, path::Path};

use dare_a2a_security::{
    budget::AdmissionLedger as A2aLedger,
    corpus::{corpus as a2a_corpus, scenario_for as a2a_scenario_for, CorpusAdapter as A2aCorpus},
    harness::A2aAdapter,
    source::A2aMode,
};
use dare_supply_chain_security::source::SupplyChainMode;

fn pretty(value: &impl serde::Serialize) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    bytes
}

/// (relative path, bytes)
fn documents() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();

    // A2A: the first corpus entry whose staged evidence has a delegation chain.
    let (entry, evidence) = a2a_corpus()
        .into_iter()
        .find_map(|entry| {
            let scenario = a2a_scenario_for(&entry);
            let evidence = A2aCorpus.collect(&scenario, &mut A2aLedger::new()).ok()?;
            (!evidence.delegation_chains.is_empty() && !evidence.exchanges.exchanges.is_empty())
                .then_some((entry, evidence))
        })
        .expect("an A2A corpus entry with delegation and exchanges");
    let mut scenario = a2a_scenario_for(&entry);
    scenario.mode = A2aMode::Static;
    scenario.reference_behavior = None;
    let mut files = Vec::new();
    for card in &evidence.cards {
        let name = format!("{}-card.json", card.card_id);
        out.push((format!("a2a/evidence/{name}"), pretty(card)));
        files.push(name);
    }
    out.push((
        "a2a/evidence/peers.json".into(),
        pretty(&evidence.peers.peers),
    ));
    out.push((
        "a2a/evidence/trace.json".into(),
        pretty(&evidence.exchanges.exchanges),
    ));
    out.push((
        "a2a/evidence/delegation.json".into(),
        pretty(&evidence.delegation_chains),
    ));
    out.push(("a2a/evidence/policy.json".into(), pretty(&evidence.policy)));
    files.extend(["peers.json", "trace.json", "delegation.json", "policy.json"].map(str::to_owned));
    scenario.evidence_files = files;
    out.push(("a2a/scenario.json".into(), pretty(&scenario)));

    // Supply chain: one CycloneDX document (the engine's own test shape) and
    // a manifest that declares and expects its dependency edge.
    let sha = "a".repeat(64);
    let bom = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "components": [
            {"type": "library", "name": "left-pad", "version": "1.3.0",
             "bom-ref": "left-pad", "purl": "pkg:npm/left-pad@1.3.0",
             "hashes": [{"alg": "SHA-256", "content": sha}]},
            {"type": "application", "name": "support-agent", "version": "1.0.0",
             "bom-ref": "support-agent"}
        ],
        "dependencies": [{"ref": "support-agent", "dependsOn": ["left-pad"]}]
    });
    out.push(("supply-chain/evidence/app.cdx.json".into(), pretty(&bom)));
    let manifest = serde_json::json!({
        "schema_version": "1",
        "manifest_id": "support-agent",
        "declared_component_ids": ["left-pad", "support-agent"],
        "expected_edges": [{"source_id": "support-agent", "target_id": "left-pad", "relation": "DEPENDS_ON"}]
    });
    out.push((
        "supply-chain/evidence/manifest.json".into(),
        pretty(&manifest),
    ));
    let mut sc = dare_supply_chain_security::corpus::scenario_for(
        &dare_supply_chain_security::corpus::corpus()[0],
    );
    sc.scenario_id = "supply-static-001".into();
    sc.mode = SupplyChainMode::Static;
    sc.reference_behavior = None;
    sc.evidence_files = vec!["app.cdx.json".into(), "manifest.json".into()];
    out.push(("supply-chain/scenario.json".into(), pretty(&sc)));
    out
}

fn root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/static-inputs")
}

#[test]
#[ignore = "writes fixtures; run explicitly to regenerate"]
fn generate() {
    for (relative, bytes) in documents() {
        let path = root().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
}

#[test]
fn committed_static_inputs_match_the_generator() {
    for (relative, bytes) in documents() {
        let committed = fs::read(root().join(&relative)).unwrap_or_default();
        assert_eq!(committed, bytes, "{relative} is stale; regenerate it");
    }
}
