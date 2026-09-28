//! Cycle 023 must not change v1 output. These digests were recorded in
//! `DARE/cycles/023-attack-path-construction/BASELINE.md` from the CLI built at
//! `32909ea`; the steps below are the ones `validate attack-graph` performs.
use dare_attack_graph::{
    build_attack_graph, derive_paths, graph_digest, validate_graph, GraphFactsInput, PathOptions,
};
use sha2::{Digest, Sha256};

const GOLDEN: [(&str, &str, &str, &str); 5] = [
    (
        "auth-mutation",
        include_str!("../../../fixtures/attack-graph/auth-mutation.json"),
        "3a20f568f797865f3f04b202289a686c3e4d157b8c7d38017de1f0669d220c1d",
        "2ade4af40b9aea3d1232bbde837dc585afeb64889dafab47a98f835ef5f67bf3",
    ),
    (
        "blocked-destructive",
        include_str!("../../../fixtures/attack-graph/blocked-destructive.json"),
        "946b473e217122750d98382343e685886c0e741fb5acf6abad4a2979c1663368",
        "68b19c5d50e6a625afc2f5c2d650999c2051b4e7f0b31cae5be5dcff5fba9049",
    ),
    (
        "confused-deputy",
        include_str!("../../../fixtures/attack-graph/confused-deputy.json"),
        "e7115fdda69858de6a2b5ac13f464fa7c334db69b59a37879bba2667c5459d40",
        "9738dd799937d46b813a9237188dba09c3d50651b8939043a37db45c77bb69aa",
    ),
    (
        "inferred-credential",
        include_str!("../../../fixtures/attack-graph/inferred-credential.json"),
        "2ebd980b199f7da5044965274bbece2ea7c701654f2faea8fc79454cbc6bcb1d",
        "3ff54b10ed6bbc1ed05648d064daa7ba1fd559f281e42170cdbf1171330ad59e",
    ),
    (
        "safe-read",
        include_str!("../../../fixtures/attack-graph/safe-read.json"),
        "910c73ab010caeaed784b9f4d125917215230f082e630a6bbb0542286b3d315a",
        "d9c34582b567516de250e23e5e2beaa7a692d0d3a9b298217595b0eeb0ccc04a",
    ),
];

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn v1_output_is_byte_identical_to_the_baseline() {
    for (name, raw, graph_sha, paths_sha) in GOLDEN {
        let facts: GraphFactsInput = serde_json::from_str(raw).unwrap();
        let mut graph = build_attack_graph(&facts).unwrap();
        graph.paths = derive_paths(&graph, &PathOptions::default()).unwrap();
        graph.id = format!("graph:{}", graph_digest(&graph).unwrap());
        validate_graph(&graph).unwrap();
        assert_eq!(
            hex(&serde_json::to_vec_pretty(&graph).unwrap()),
            graph_sha,
            "{name} attack-graph.json"
        );
        assert_eq!(
            hex(&serde_json::to_vec_pretty(&graph.paths).unwrap()),
            paths_sha,
            "{name} paths.json"
        );
    }
}
