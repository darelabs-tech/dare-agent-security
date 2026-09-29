//! Containment (BLUEPRINT RNF-04, RS-05, RS-08): the only DARE dependency is
//! the graph contract, nothing declared can reach a network, spawn a process
//! or schedule work, the source uses none of those, and no crate other than
//! the CLI depends on this one.
use std::{fs, path::Path};

const MANIFEST: &str = include_str!("../Cargo.toml");

fn section<'a>(manifest: &'a str, header: &str) -> &'a str {
    let start = manifest.find(header).expect("section present") + header.len();
    let rest = &manifest[start..];
    let end = rest.find("\n[").map_or(rest.len(), |i| i + 1);
    &rest[..end]
}

fn dependency_names(section: &str) -> Vec<String> {
    section
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split('=').next())
        .map(|name| name.trim().to_owned())
        .collect()
}

#[test]
fn the_dependencies_are_exactly_the_blueprint_list() {
    let mut deps = dependency_names(section(MANIFEST, "[dependencies]"));
    deps.sort();
    assert_eq!(
        deps,
        [
            "dare-attack-graph",
            "jsonschema",
            "serde",
            "serde_json",
            "sha2",
            "thiserror"
        ]
    );
    assert_eq!(
        dependency_names(section(MANIFEST, "[dev-dependencies]")),
        ["tempfile"]
    );
}

#[test]
fn the_source_reaches_no_socket_process_thread_or_environment() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut scanned = 0;
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let text = fs::read_to_string(&path).unwrap();
        for forbidden in [
            "std::net",
            "std::process",
            "std::thread",
            "std::env",
            "env::var",
            "TcpStream",
            "UdpSocket",
            "Command::new",
            "dare_attack_path",
        ] {
            assert!(
                !text.contains(forbidden),
                "{} uses {forbidden}",
                path.display()
            );
        }
        scanned += 1;
    }
    assert!(scanned >= 3);
}

#[test]
fn only_the_cli_depends_on_this_crate() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    for entry in fs::read_dir(crates).unwrap() {
        let dir = entry.unwrap().path();
        let manifest = dir.join("Cargo.toml");
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        if !manifest.is_file() || name == "dare-blast-radius" || name == "dare-agent-security-cli" {
            continue;
        }
        let text = fs::read_to_string(&manifest).unwrap();
        assert!(
            !text.contains("dare-blast-radius"),
            "{name} must not depend on dare-blast-radius"
        );
    }
}
