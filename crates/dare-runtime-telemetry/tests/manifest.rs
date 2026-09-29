//! Containment (BLUEPRINT AD-01, RNF-04, RS-08): exactly the Blueprint's
//! dependencies, no source that reaches a socket, process, thread or the
//! environment, and no crate other than the CLI depends on this one.
use std::{fs, path::Path};

const MANIFEST: &str = include_str!("../Cargo.toml");

fn section<'a>(manifest: &'a str, header: &str) -> &'a str {
    let start = manifest.find(header).expect("section present") + header.len();
    let rest = &manifest[start..];
    let end = rest.find("\n[").map_or(rest.len(), |i| i + 1);
    &rest[..end]
}

fn dependency_names(section: &str) -> Vec<String> {
    let mut names: Vec<String> = section
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split('=').next())
        .map(|name| name.trim().to_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn the_dependencies_are_exactly_the_blueprint_list() {
    assert_eq!(
        dependency_names(section(MANIFEST, "[dependencies]")),
        [
            "dare-coverage",
            "dare-security-evidence",
            "jsonschema",
            "serde",
            "serde_json",
            "sha2",
            "thiserror"
        ]
    );
    assert_eq!(
        dependency_names(section(MANIFEST, "[dev-dependencies]")),
        ["dare-attack-graph", "tempfile"]
    );
}

#[test]
fn the_source_reaches_no_socket_process_thread_or_environment() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut scanned = 0;
    let mut stack = vec![dir];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            for forbidden in [
                "std::net",
                "std::process",
                "std::thread",
                "std::env",
                "env::var",
                "TcpStream",
                "TcpListener",
                "UdpSocket",
                "Command::new",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "{} uses {forbidden}",
                    path.display()
                );
            }
            scanned += 1;
        }
    }
    assert!(scanned >= 1);
}

#[test]
fn only_the_cli_depends_on_this_crate() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for entry in fs::read_dir(&crates).unwrap() {
        let dir = entry.unwrap().path();
        let manifest = dir.join("Cargo.toml");
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        if !manifest.exists() || name == "dare-runtime-telemetry" {
            continue;
        }
        let text = fs::read_to_string(&manifest).unwrap();
        if text.contains("dare-runtime-telemetry") {
            assert_eq!(name, "dare-agent-security-cli", "{name} depends on it");
        }
    }
}
