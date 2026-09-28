//! Containment (BLUEPRINT AD-03, RNF-04, RS-07): this crate declares no
//! network, process or scheduler dependency, its source reaches none, and no
//! crate other than the CLI depends on it.
use std::{fs, path::Path};

const MANIFEST: &str = include_str!("../Cargo.toml");

fn section<'a>(manifest: &'a str, header: &str) -> &'a str {
    let start = manifest.find(header).expect("section present") + header.len();
    let rest = &manifest[start..];
    let end = rest.find("\n[").map_or(rest.len(), |i| i + 1);
    &rest[..end]
}

#[test]
fn no_network_process_or_scheduler_dependency_is_declared() {
    let deps = section(MANIFEST, "[dependencies]");
    for forbidden in [
        "reqwest",
        "hyper",
        "rmcp",
        "tokio",
        "axum",
        "ureq",
        "openssl",
        "native-tls",
        "dare-remote-validation",
        "dare-mcp-discovery",
        "dare-continuous",
    ] {
        assert!(
            !deps
                .lines()
                .any(|line| line.trim_start().starts_with(forbidden)),
            "{forbidden} must not be a dependency of dare-attack-path"
        );
    }
}

#[test]
fn the_source_reaches_no_socket_process_or_thread_pool() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![dir];
    let mut scanned = 0;
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(&path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let text = fs::read_to_string(&path).unwrap();
            for forbidden in [
                "std::net",
                "std::process",
                "TcpStream",
                "UdpSocket",
                "Command::new",
                "std::thread::spawn",
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
    assert!(scanned > 0);
}

#[test]
fn only_the_cli_depends_on_this_crate() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    for entry in fs::read_dir(crates).unwrap() {
        let dir = entry.unwrap().path();
        let manifest = dir.join("Cargo.toml");
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        if !manifest.is_file() || name == "dare-attack-path" || name == "dare-agent-security-cli" {
            continue;
        }
        let text = fs::read_to_string(&manifest).unwrap();
        assert!(
            !text.contains("dare-attack-path"),
            "{name} must not depend on dare-attack-path (BQ-3 (a))"
        );
    }
}
