//! Compatibility with everything that existed before Cycle 021.
//!
//! Digests below were computed from `main @ 4ca06b2` (the Cycle 021 baseline)
//! over canonical JSON (sorted keys, compact). A change to any pre-existing
//! registry entry or profile changes its digest and fails here.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

const REGISTRY_JSON: &str = include_str!("../../../schemas/coverage/v2/registry.json");
const BASELINE_REGISTRY_COUNT: usize = 58;
const BASELINE_REGISTRY_DIGEST: &str =
    "73f6ea31cf360cade6b72f6e739bf35891d3c01afb415962d1e3c7cfca9216b2";

const BASELINE_PROFILES: [(&str, &str); 10] = [
    (
        "mcp-security-baseline",
        "f175bc105cae3144c54b295cd912d8f16a1068cbcf6c4dda43d4d76f2a11bf04",
    ),
    (
        "agentic-security-baseline-2026",
        "2f3d46a7e9f609748b2f7163b1a43802c6e670611dc508a7dbb80d5ed2adc08d",
    ),
    (
        "prompt-injection-baseline-2026",
        "2ccc4f916a00126fab29d3b4f19d9db5c3133551bac0a47d3727517ef762c729",
    ),
    (
        "tool-security-baseline-2026",
        "701f9cb2b4d3bd5e00bfb7aad7f70be1c44d0943560883f447b8538feb203f16",
    ),
    (
        "identity-security-baseline-2026",
        "4e51deca106c907da776516ba0851ec6efa1132fb0b00af5c2e403d3fefdf6be",
    ),
    (
        "memory-security-baseline-2026",
        "ee272b9d09e896a838379e24ea0bca3d344308653366f71c3b2e4016a4d2fd54",
    ),
    (
        "rag-security-baseline-2026",
        "3e64fae1e1c98f824c5e609df304912bedd1abfcd1031e93e93988609ca13003",
    ),
    (
        "mcp-auth-hardening-2026",
        "c2d4faae111b1bdfe8604e3e455033842ede7f094cd04fadde8f6a41684555a5",
    ),
    (
        "agentic-supply-chain-security-2026",
        "16c32a58687a633681b107f2c832bd24e0dbd08ef606db3fcdc09fc2512622e8",
    ),
    (
        "agentic-a2a-security-2026",
        "c5f5f4b20e81f7a4723d373602b537c804a8acc99fab22a957b44e195eaf2929",
    ),
];

fn canonical_digest(value: &serde_json::Value) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_string(value).expect("json").as_bytes())
    )
}

fn repo(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

#[test]
fn every_pre_existing_registry_entry_is_byte_for_byte_unchanged() {
    let registry: serde_json::Value = serde_json::from_str(REGISTRY_JSON).expect("json");
    let properties = registry["properties"].as_array().expect("array");
    let original = serde_json::Value::Array(properties[..BASELINE_REGISTRY_COUNT].to_vec());
    assert_eq!(canonical_digest(&original), BASELINE_REGISTRY_DIGEST);
}

#[test]
fn every_earlier_profile_is_unchanged() {
    for (name, digest) in BASELINE_PROFILES {
        let raw =
            std::fs::read_to_string(repo(&format!("profiles/{name}.json"))).expect("readable");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(canonical_digest(&value), digest, "{name} changed");
    }
}

#[test]
fn this_crate_takes_no_single_turn_engine_as_a_dependency() {
    // Verdict authority over single-turn properties stays with Cycles 013–020;
    // the simplest proof that this crate does not borrow it is that it cannot
    // call them.
    let manifest = include_str!("../Cargo.toml");
    for engine in [
        "dare-prompt-injection",
        "dare-tool-security",
        "dare-identity-security",
        "dare-memory-security",
        "dare-rag-security",
        "dare-mcp-auth-security",
        "dare-supply-chain-security",
        "dare-a2a-security",
    ] {
        assert!(
            !manifest.contains(engine),
            "{engine} would couple Cycle 021 to a single-turn engine"
        );
    }
}

/// Directories the root `Dockerfile` copies into the Action image builder.
fn docker_copied_dirs() -> BTreeSet<String> {
    let dockerfile = std::fs::read_to_string(repo("Dockerfile")).expect("root Dockerfile");
    dockerfile
        .lines()
        .filter_map(|line| line.strip_prefix("COPY "))
        .filter(|rest| !rest.starts_with("--from"))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(|src| src.trim_end_matches('/').to_owned())
        .collect()
}

#[test]
fn embedded_assets_live_in_docker_copied_dirs() {
    // Blueprint AD-10: the Action image must keep building. Cycle 012 broke it
    // by embedding a file from a directory the Dockerfile did not copy.
    let copied = docker_copied_dirs();
    assert!(
        copied.contains("crates") && copied.contains("schemas"),
        "{copied:?}"
    );
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = crate_dir.join("../..").canonicalize().expect("root");
    let mut checked = 0;
    for dir in ["src", "tests"] {
        for entry in std::fs::read_dir(crate_dir.join(dir)).expect("dir") {
            let path = entry.expect("entry").path();
            let text = std::fs::read_to_string(&path).expect("source");
            for (index, _) in text.match_indices("include_str!(\"") {
                let rest = &text[index + "include_str!(\"".len()..];
                let target = &rest[..rest.find('"').expect("closing quote")];
                let resolved = path
                    .parent()
                    .expect("parent")
                    .join(target)
                    .canonicalize()
                    .expect("embedded file exists");
                let relative = resolved.strip_prefix(&root).expect("inside the repository");
                let top = relative
                    .components()
                    .next()
                    .expect("component")
                    .as_os_str()
                    .to_string_lossy()
                    .into_owned();
                assert!(
                    copied.contains(&top),
                    "{} embeds {} from `{top}/`, which the Dockerfile does not copy",
                    path.display(),
                    relative.display()
                );
                checked += 1;
            }
        }
    }
    assert!(checked >= 5, "only {checked} embedded assets found");
}

#[test]
fn the_ci_trigger_is_still_pull_request_opened_only() {
    let ci = std::fs::read_to_string(repo(".github/workflows/ci.yml")).expect("ci.yml");
    let head: String = ci.lines().take(8).collect::<Vec<_>>().join("\n");
    assert!(
        head.contains("pull_request:") && head.contains("types: [opened]"),
        "{head}"
    );
    assert!(ci.contains("  multi-turn-security-2026:"));
}
