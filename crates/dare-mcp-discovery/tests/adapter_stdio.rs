//! stdio argv handling: executable + args, no shell interpolation.

use dare_mcp_discovery::{DiscoveryTargetKind, DiscoveryTargetSpec, StdioLaunch};

#[test]
fn command_is_built_from_program_and_args() {
    let launch = StdioLaunch::new(
        "/usr/local/bin/synthetic-mcp",
        vec!["--stdio".to_owned(), "--passive".to_owned()],
    )
    .expect("launch");
    assert_eq!(launch.program(), "/usr/local/bin/synthetic-mcp");
    assert_eq!(launch.args(), ["--stdio", "--passive"]);
    assert!(!launch.uses_shell());
    assert!(!launch.inherits_full_environment());

    let cmd = launch.to_tokio_command();
    let std = cmd.as_std();
    assert_eq!(std.get_program(), "/usr/local/bin/synthetic-mcp");
    let args: Vec<String> = std
        .get_args()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    assert_eq!(args, ["--stdio", "--passive"]);
}

#[test]
fn spec_stdio_constructor_stores_argv() {
    let spec = DiscoveryTargetSpec::stdio("mcp-server", vec!["a".to_owned(), "b".to_owned()])
        .expect("spec");
    match spec.target {
        DiscoveryTargetKind::Stdio { program, args } => {
            assert_eq!(program, "mcp-server");
            assert_eq!(args, ["a", "b"]);
        }
        DiscoveryTargetKind::Http { .. } => panic!("expected stdio target"),
    }
}

#[test]
fn concatenated_shell_string_is_not_used_as_argv() {
    let launch = StdioLaunch::new("mcp-server", vec!["--flag".to_owned()]).expect("launch");
    let cmd = launch.to_tokio_command();
    let joined = format!(
        "{} {}",
        cmd.as_std().get_program().to_string_lossy(),
        cmd.as_std()
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    );
    assert!(!joined.contains("&&"));
    assert!(!joined.contains("|"));
    assert!(!joined.contains("cmd /c"));
}
