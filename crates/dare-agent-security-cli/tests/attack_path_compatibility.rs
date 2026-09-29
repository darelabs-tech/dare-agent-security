//! Cycle 023 compatibility (BLUEPRINT §8.4, task-043).
//!
//! - A v2 path's `(id, status, impact_factors)` passes Cycle 009's
//!   `ensure_path_eligible` exactly as the v1 path with the same id does, so a
//!   validation plan can pin either (RF-17).
//! - The coverage registries and every profile keep their baseline bytes.
//! - The ten engine crates (013–022) keep their baseline trees: this cycle
//!   reads their public items and changes none of them.
//! - Every `include_str!` of the crates this cycle touches lies under a
//!   directory the Dockerfile copies, so the image still builds.
//!
//! Every digest below was computed from `main @ 32909ea` (the Cycle 023
//! baseline, `BASELINE.md`) and verified equal to the tree when this file was
//! written. The v1 golden digests are in `dare-attack-graph/tests/v1_unchanged.rs`.
use std::{
    fs,
    path::{Path, PathBuf},
};

use dare_adversarial::{eligibility::ensure_path_eligible, ValidationBundle};
use dare_attack_graph::{
    build_attack_graph, derive_paths,
    v2::{impact_factors, path_id, path_status, EdgeV2, Guard, GuardScope, GuardVerdict, NodeV2},
    GraphFactsInput, PathOptions,
};
use dare_attack_path::ids::sha256_prefixed;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sha(bytes: &[u8]) -> String {
    sha256_prefixed(bytes)[7..].to_owned()
}

/// Each v1 fixture's graph seen as v2 facts, the way `dare-attack-path`
/// carries a v1 FAIL: as a FAIL guard on the edge.
fn as_v2(graph: &dare_attack_graph::AttackGraph) -> (Vec<NodeV2>, Vec<EdgeV2>) {
    let nodes = graph
        .nodes
        .iter()
        .map(|n| NodeV2 {
            id: n.id.clone(),
            node_type: n.node_type,
            display_name: n.display_name.clone(),
            security: n.security.clone(),
            provenance: vec![],
        })
        .collect();
    let edges = graph
        .edges
        .iter()
        .map(|e| EdgeV2 {
            id: e.id.clone(),
            edge_type: e.edge_type,
            source: e.source.clone(),
            target: e.target.clone(),
            authority: e.authority.clone(),
            evidence: e.evidence.clone(),
            guards: (e.security.verdict.as_deref() == Some("FAIL"))
                .then(|| Guard {
                    property: e.security.property.clone().unwrap_or_default(),
                    verdict: GuardVerdict::Fail,
                    evidence_ids: vec![],
                    scope: GuardScope::Run,
                    artifact_index: 0,
                })
                .into_iter()
                .collect(),
            authority_mutation: e.security.authority_mutation,
            crosses_trust_boundary: vec![],
            provenance: vec![],
        })
        .collect();
    (nodes, edges)
}

#[test]
fn a_v2_path_is_eligible_exactly_when_the_v1_path_with_its_id_is() {
    let bundles: Vec<ValidationBundle> = fs::read_dir(repo().join("fixtures/adversarial"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter_map(|p| dare_adversarial::load_bundle(&p).ok())
        .collect();
    assert!(bundles.len() >= 5, "adversarial fixtures load");
    let mut compared = 0;
    let mut eligible = 0;
    for name in [
        "auth-mutation",
        "blocked-destructive",
        "confused-deputy",
        "inferred-credential",
        "safe-read",
    ] {
        let facts: GraphFactsInput = serde_json::from_slice(
            &fs::read(repo().join(format!("fixtures/attack-graph/{name}.json"))).unwrap(),
        )
        .unwrap();
        let graph = build_attack_graph(&facts).unwrap();
        let paths = derive_paths(&graph, &PathOptions::default()).unwrap();
        let (nodes, edges) = as_v2(&graph);
        for v1 in &paths {
            let path_nodes: Vec<&NodeV2> = v1
                .nodes
                .iter()
                .map(|id| nodes.iter().find(|n| &n.id == id).unwrap())
                .collect();
            let path_edges: Vec<&EdgeV2> = v1
                .edges
                .iter()
                .map(|id| edges.iter().find(|e| &e.id == id).unwrap())
                .collect();
            // The v2 path's own fields, computed by v2 code.
            let mut v2 = v1.clone();
            v2.id = path_id(&v1.nodes, &v1.edges).unwrap();
            v2.status = path_status(&path_edges);
            v2.impact_factors = impact_factors(&path_nodes, &path_edges).v1;
            assert_eq!(v2.id, v1.id, "{name}: same id formula");
            assert_eq!(v2.status, v1.status, "{name} {}", v1.id);
            assert_eq!(v2.impact_factors, v1.impact_factors, "{name} {}", v1.id);
            for bundle in &bundles {
                let mut plan = bundle.plan.clone();
                plan.attack_path_id = v1.id.clone();
                for roe_valid in [false, true] {
                    let a = ensure_path_eligible(v1, &plan, &bundle.budget, roe_valid);
                    let b = ensure_path_eligible(&v2, &plan, &bundle.budget, roe_valid);
                    assert_eq!(
                        format!("{a:?}"),
                        format!("{b:?}"),
                        "{name} {} roe={roe_valid}",
                        v1.id
                    );
                    eligible += usize::from(a.is_ok());
                    compared += 1;
                }
            }
        }
    }
    assert!(compared >= 50, "{compared}");
    assert!(
        eligible > 0,
        "some path is eligible, so both outcomes are covered"
    );
}

/// The coverage registry may only grow at its end (Cycle 025 BQ-1, the Cycle 021
/// prefix rule): its first bytes, through the closing brace of the last property
/// that existed at the Cycle 022 baseline, stay byte-identical, and anything after
/// them is either the original closing tail or an appended `,` + new entries.
const REGISTRY_PREFIX: (&str, usize, &str) = (
    "schemas/coverage/v2/registry.json",
    63_498,
    "5364f9dcae24e08e2aa90163d7f92cf08afb3f6cb7f9dffaa0666625fef91ec4",
);

/// The v1 registry and every earlier profile, byte for byte.
const UNCHANGED_FILES: [(&str, &str); 12] = [
    (
        "schemas/coverage/v1/registry.json",
        "155ba470453ab59654a48b5cf29b40278137d126427bde394188b4af4b7fed71",
    ),
    (
        "profiles/agentic-a2a-security-2026.json",
        "ffab75393a7901e66b554da888b073396b29ee6877c27644f2445ba6db89cb53",
    ),
    (
        "profiles/agentic-security-baseline-2026.json",
        "ef44fbd5c92e77d8be7d9785686a23b2dec7cb25104724deb548963bfc713c12",
    ),
    (
        "profiles/agentic-supply-chain-security-2026.json",
        "7af34fbe3ebbee8675fc1f36ed3009270a37091e20446aa380f1165304e5ba8f",
    ),
    (
        "profiles/identity-security-baseline-2026.json",
        "66bd88e4e71211c6b8dca52bdd1bd550497890e12e94d1fe261a2e8bd492cba3",
    ),
    (
        "profiles/mcp-auth-hardening-2026.json",
        "df178dc45ad3c62f45af24177fe63d772b1af669b6b25f0a44b56801df2be0df",
    ),
    (
        "profiles/mcp-security-baseline.json",
        "5a703f19dec6685c65eac520ba28d85afe218095de728f5df564c482bd42f7a6",
    ),
    (
        "profiles/memory-security-baseline-2026.json",
        "41ccd33adcd3aee4cc0dad55aab88a014a5749d9489d09a75ae32f0ae2798776",
    ),
    (
        "profiles/multi-turn-security-baseline-2026.json",
        "e94fe1965619d73cb6f14e60c819e7b05ce435ed7d77e0b1d25347a6a4ab3130",
    ),
    (
        "profiles/prompt-injection-baseline-2026.json",
        "cb30793eeff7ae9181c511104a97e5659e2acf2e09332abf27c813895e6f3e95",
    ),
    (
        "profiles/rag-security-baseline-2026.json",
        "9c55108e32d78d67589f6ca10fc1b159d131bb588f91ae8660089c9464fcf02b",
    ),
    (
        "profiles/tool-security-baseline-2026.json",
        "f7855bb3588d56bb777fedad64d8671f11782d78d45883a6ce22313af03188b5",
    ),
];

#[test]
fn the_registries_and_every_profile_are_unchanged() {
    let (file, length, digest) = REGISTRY_PREFIX;
    let registry = fs::read(repo().join(file)).unwrap();
    assert!(registry.len() >= length, "{file} shrank");
    assert_eq!(
        sha(&registry[..length]),
        digest,
        "{file}: an existing entry changed"
    );
    let rest = &registry[length..];
    assert!(
        rest == b"\n  ]\n}\n" || rest.starts_with(b",\n"),
        "{file}: only appended entries may follow the existing ones"
    );
    for (file, digest) in UNCHANGED_FILES {
        assert_eq!(sha(&fs::read(repo().join(file)).unwrap()), digest, "{file}");
    }
    let profiles = fs::read_dir(repo().join("profiles"))
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|x| x == "json")
        })
        .count();
    // The 11 earlier profiles are pinned above; Cycle 025 may add its own.
    assert!(profiles >= 11, "no earlier profile removed");
}

/// (crate, tree digest, file count). The tree digest is SHA-256 over
/// `<relative path>\0<sha256 of the file>\n` for every file, sorted by path.
const ENGINE_TREES: [(&str, &str, usize); 10] = [
    (
        "dare-prompt-injection",
        "3600a290ee728f3a4dcf26bc4233012a073f39a4f52f384b1dcd69ea6665f830",
        23,
    ),
    (
        "dare-tool-security",
        "e7cb9942e524ef43499a6008bb088ac1a693cc27ec17cf3ebf879e6983251652",
        22,
    ),
    (
        "dare-identity-security",
        "27c601a792c8de0d8d659a9cb9cb61790e5dc7a3e066950859b74ebe7bb45343",
        54,
    ),
    (
        "dare-memory-security",
        "fa1daf59d77a01dd04757a9b57a028f22c41764db02e6020748581021bd14c19",
        53,
    ),
    (
        "dare-rag-security",
        "5f2afab101c294e85e5bab0bc9e5b8f6592ed9e3380606b9ee1ef4904b70d905",
        51,
    ),
    (
        "dare-mcp-auth-security",
        "0ef431c4e441b53b87ce50aa192f5646967d00a7d9fca1105ee883107db55708",
        77,
    ),
    (
        "dare-supply-chain-security",
        "ddade3831d0ff518a6dac44bd082fbae9d5c9fb8c4df60539db663873d3ede4a",
        33,
    ),
    (
        "dare-a2a-security",
        "e0d075d64c22c1e681ab147ca8f7b56e43de287e8d2300cea9955285296212a2",
        36,
    ),
    (
        "dare-multi-turn-security",
        "60ad42d8b675e0d94c2b211757e61e740f782ad4b38bde3c306b1a1a3ba73add",
        27,
    ),
    (
        "dare-remote-validation",
        "e13f3c63a086dc4c772ca746beccdadb586ac13985f07c252b3b1b3d0c07b098",
        52,
    ),
];

fn files(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            files(root, &path, out);
        } else {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((relative, sha(&fs::read(&path).unwrap())));
        }
    }
}

#[test]
fn the_engine_crates_are_unchanged() {
    for (name, digest, count) in ENGINE_TREES {
        let root = repo().join("crates").join(name);
        let mut list = Vec::new();
        files(&root, &root, &mut list);
        list.sort();
        let joined: String = list
            .iter()
            .map(|(path, hash)| format!("{path}\0{hash}\n"))
            .collect();
        assert_eq!(list.len(), count, "{name}: file count");
        assert_eq!(sha(joined.as_bytes()), digest, "{name}: tree changed");
    }
}

/// Directories the Dockerfile's builder stage copies.
fn docker_copied() -> Vec<String> {
    let dockerfile = fs::read_to_string(repo().join("Dockerfile")).unwrap();
    dockerfile
        .lines()
        .filter_map(|l| l.strip_prefix("COPY "))
        .filter(|l| !l.starts_with("--from"))
        .filter_map(|l| l.split_whitespace().next())
        .map(|s| s.trim_end_matches('/').to_owned())
        .collect()
}

#[test]
fn every_include_str_lies_under_a_docker_copied_directory() {
    let copied = docker_copied();
    assert!(copied.iter().any(|c| c == "schemas"), "{copied:?}");
    let mut found = 0;
    for krate in [
        "dare-attack-path",
        "dare-attack-graph",
        "dare-product",
        "dare-agent-security-cli",
    ] {
        let src = repo().join("crates").join(krate).join("src");
        let mut sources = Vec::new();
        files(&src, &src, &mut sources);
        for (relative, _) in sources {
            let file = src.join(&relative);
            let text = fs::read_to_string(&file).unwrap_or_default();
            for part in text.split("include_str!(\"").skip(1) {
                let target = part.split('"').next().unwrap();
                let resolved = file.parent().unwrap().join(target);
                let resolved = resolved
                    .canonicalize()
                    .unwrap_or_else(|_| panic!("{krate}/{relative}: {target} missing"));
                let from_repo = resolved
                    .strip_prefix(repo().canonicalize().unwrap())
                    .unwrap_or_else(|_| panic!("{target} leaves the repository"));
                let top = from_repo
                    .components()
                    .next()
                    .unwrap()
                    .as_os_str()
                    .to_string_lossy()
                    .into_owned();
                assert!(
                    copied.contains(&top),
                    "{krate}/{relative}: {target} is under `{top}`, which the Dockerfile does not copy"
                );
                found += 1;
            }
        }
    }
    assert!(found >= 6, "{found}");
}
