//! Compatibility with everything that existed before Cycle 022.
//!
//! Every digest below was computed from `main @ b6f14b9` (the Cycle 022
//! baseline) and verified equal to the current tree when this file was
//! written. The engines' own no-network tests are pinned by digest so that
//! adding network capability here could not have been done by weakening them.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

fn repo(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The region of each file holding an engine's no-network test: the whole
/// file for `tests/offline_confidential.rs`, the last `#[cfg(test)]` module
/// onwards for a `lib.rs`.
const NO_NETWORK_TESTS: [(&str, &str); 7] = [
    (
        "crates/dare-prompt-injection/tests/offline_confidential.rs",
        "706ddf32573a156bff963c4078dd4d7a99fe614a089f405f3143804fda0fc217",
    ),
    (
        "crates/dare-rag-security/tests/offline_confidential.rs",
        "d43e8f21cbab1686fd192e60e03cac06bf3a42c21f32114d0caff6860e421dff",
    ),
    (
        "crates/dare-tool-security/tests/offline_confidential.rs",
        "e4f26e53a20e142f47b65e65f0ba85bdac96de9d78a9c95a3d7b3e63151c19a6",
    ),
    (
        "crates/dare-a2a-security/src/lib.rs",
        "1cc57ce6b7a6df269884e47ef33246de980a083c028a47f7b7f88b3170b8b9a3",
    ),
    (
        "crates/dare-multi-turn-security/src/lib.rs",
        "6a105c13181b295c707e1945b5e1f1852f7978d796b73918cb9586509407a899",
    ),
    (
        "crates/dare-mcp-auth-security/src/lib.rs",
        "8bfd7bddfb4e4671f9887d8295a46bf26e81828f4541877d64a3c0c2f5509338",
    ),
    (
        "crates/dare-supply-chain-security/src/lib.rs",
        "a28dee353c00d9b505d25bcf0f083132d8927689f977a7698b80afb51c29a471",
    ),
];

/// Byte digests of the coverage registry and every profile.
const UNCHANGED_FILES: [(&str, &str); 12] = [
    (
        "schemas/coverage/v2/registry.json",
        "e8c5004c920c53606949ad537fb24d1e2f5d50ba23b26a75081afedf0f9737e9",
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

const ROE_RS: &str = "55eed6409a6677bac3ea2f46607a0639f6ef5f285f7fe4818799533068f623e4";

#[test]
fn every_engine_no_network_test_is_unchanged() {
    for (path, digest) in NO_NETWORK_TESTS {
        let text = std::fs::read_to_string(repo(path)).expect("readable");
        let region = if path.ends_with("lib.rs") {
            &text[text.rfind("#[cfg(test)]").expect("a test module")..]
        } else {
            text.as_str()
        };
        assert!(
            region.contains("\"reqwest\""),
            "{path} still names the forbidden transport"
        );
        assert_eq!(
            sha(region.as_bytes()),
            digest,
            "{path}: an engine's no-network test changed"
        );
    }
}

#[test]
fn the_registry_and_every_profile_are_byte_for_byte_unchanged() {
    for (path, digest) in UNCHANGED_FILES {
        assert_eq!(
            sha(&std::fs::read(repo(path)).expect("readable")),
            digest,
            "{path} changed"
        );
    }
    let profiles = std::fs::read_dir(repo("profiles"))
        .expect("profiles")
        .count();
    assert_eq!(
        profiles,
        UNCHANGED_FILES.len() - 1,
        "Cycle 022 adds no profile"
    );
}

#[test]
fn dare_adversarial_still_refuses_non_local_execution() {
    let roe = std::fs::read(repo("crates/dare-adversarial/src/roe.rs")).expect("roe.rs");
    assert_eq!(sha(&roe), ROE_RS);
    assert!(String::from_utf8_lossy(&roe).contains("if !roe.local_only {"));
}

#[test]
fn nothing_continuous_or_adversarial_depends_on_this_crate() {
    for krate in [
        "dare-continuous",
        "dare-adversarial",
        "dare-coverage",
        "dare-security-evidence",
    ] {
        let manifest =
            std::fs::read_to_string(repo(&format!("crates/{krate}/Cargo.toml"))).expect("manifest");
        assert!(
            !manifest.contains("dare-remote-validation"),
            "{krate} reaches the network crate"
        );
    }
}

#[test]
fn no_engine_crate_depends_on_this_crate() {
    for krate in [
        "dare-prompt-injection",
        "dare-multi-turn-security",
        "dare-a2a-security",
        "dare-mcp-auth-security",
        "dare-identity-security",
        "dare-memory-security",
        "dare-rag-security",
        "dare-supply-chain-security",
        "dare-tool-security",
    ] {
        let manifest =
            std::fs::read_to_string(repo(&format!("crates/{krate}/Cargo.toml"))).expect("manifest");
        assert!(!manifest.contains("dare-remote-validation"), "{krate}");
    }
}

#[test]
fn the_cli_never_enables_the_lab_feature() {
    let manifest = std::fs::read_to_string(repo("crates/dare-agent-security-cli/Cargo.toml"))
        .expect("manifest");
    let lines: Vec<&str> = manifest
        .lines()
        .filter(|l| l.contains("dare-remote-validation"))
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "one normal dependency, no dev-dependency: {lines:?}"
    );
    assert!(
        !lines[0].contains("lab") && !lines[0].contains("features"),
        "{}",
        lines[0]
    );
    let own = include_str!("../Cargo.toml");
    let default = own
        .lines()
        .find(|l| l.trim_start().starts_with("default"))
        .unwrap_or("default = []");
    assert!(
        !default.contains("lab"),
        "lab must never be a default feature"
    );
}

/// Directories the root `Dockerfile` copies into the Action image builder.
fn docker_copied_dirs() -> BTreeSet<String> {
    std::fs::read_to_string(repo("Dockerfile"))
        .expect("root Dockerfile")
        .lines()
        .filter_map(|line| line.strip_prefix("COPY "))
        .filter(|rest| !rest.starts_with("--from"))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(|src| src.trim_end_matches('/').to_owned())
        .collect()
}

#[test]
fn embedded_assets_live_in_docker_copied_dirs() {
    let copied = docker_copied_dirs();
    let root = repo("").canonicalize().expect("root");
    let mut checked = 0;
    for dir in [
        "crates/dare-remote-validation/src",
        "crates/dare-mcp-auth-security/src",
        "crates/dare-agent-security-cli/src",
    ] {
        let mut stack = vec![repo(dir)];
        while let Some(path) = stack.pop() {
            if path.is_dir() {
                stack.extend(
                    std::fs::read_dir(&path)
                        .expect("dir")
                        .map(|e| e.expect("entry").path()),
                );
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            for (index, _) in text.match_indices("include_str!(\"") {
                let rest = &text[index + "include_str!(\"".len()..];
                let target = &rest[..rest.find('"').expect("closing quote")];
                let resolved = path
                    .parent()
                    .expect("parent")
                    .join(target)
                    .canonicalize()
                    .expect("embedded file exists");
                let top = resolved
                    .strip_prefix(&root)
                    .expect("inside")
                    .components()
                    .next()
                    .expect("component")
                    .as_os_str()
                    .to_string_lossy()
                    .into_owned();
                assert!(
                    copied.contains(&top),
                    "{} embeds from `{top}/`, which the Dockerfile does not copy",
                    path.display()
                );
                checked += 1;
            }
        }
    }
    assert!(checked >= 7, "only {checked} embedded assets found");
}

#[test]
fn the_ci_trigger_is_still_pull_request_opened_only() {
    let ci = std::fs::read_to_string(repo(".github/workflows/ci.yml")).expect("ci.yml");
    let head: String = ci.lines().take(8).collect::<Vec<_>>().join("\n");
    assert!(
        head.contains("pull_request:") && head.contains("types: [opened]"),
        "{head}"
    );
    assert!(ci.contains("  remote-validation-2026:"));
    assert!(
        ci.contains("  multi-turn-security-2026:"),
        "earlier gates are kept"
    );
}
