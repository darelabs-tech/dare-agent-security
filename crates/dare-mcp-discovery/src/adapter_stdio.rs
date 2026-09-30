//! stdio launch specification: executable + argv, never a shell string.

use std::ffi::OsStr;
use std::process::Stdio;

use tokio::process::Command;

use super::adapter_error::AdapterError;

/// Explicit OS variables required to spawn a process after `env_clear`.
///
/// Full parent environment is not inherited. These keys are copied only when
/// present in the current process.
#[cfg(windows)]
const STDIO_ENV_ALLOWLIST: &[&str] = &[
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "PATHEXT",
    "SYNTHETIC_MCP_TRACE_PATH",
];

#[cfg(not(windows))]
const STDIO_ENV_ALLOWLIST: &[&str] = &["SYNTHETIC_MCP_TRACE_PATH"];

/// Most variables an operator may pass through with `--pass-env`.
pub const MAX_PASS_ENV: usize = 32;

/// Longest variable name accepted by `--pass-env`.
const MAX_PASS_ENV_NAME: usize = 64;

/// Operator-supplied stdio child specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StdioLaunch {
    program: String,
    args: Vec<String>,
    pass_env: Vec<String>,
}

impl StdioLaunch {
    /// Build a launch spec from an executable path and argv.
    ///
    /// `program` is the executable. Arguments are passed as a list. There is
    /// no shell interpolation (`cmd.exe /c`, `sh -c`, or concatenated strings).
    pub fn new(
        program: impl Into<String>,
        args: impl Into<Vec<String>>,
    ) -> Result<Self, AdapterError> {
        let program = program.into();
        if program.is_empty() {
            return Err(AdapterError::invalid_target("empty-program"));
        }
        if looks_like_shell_wrapper(&program) {
            return Err(AdapterError::invalid_target("shell-program"));
        }
        let args = args.into();
        Ok(Self {
            program,
            args,
            pass_env: Vec::new(),
        })
    }

    /// Also copy these variables, by name, from the operator's environment.
    ///
    /// The operator names each variable; nothing else is inherited. Names must
    /// match `[A-Za-z_][A-Za-z0-9_]*` (at most 64 bytes, at most
    /// [`MAX_PASS_ENV`] names). Values are read at spawn time and are never
    /// stored in the launch spec, the inventory or any artifact.
    pub fn with_pass_env(mut self, names: &[String]) -> Result<Self, AdapterError> {
        if names.len() > MAX_PASS_ENV {
            return Err(AdapterError::invalid_target("pass-env-too-many"));
        }
        let mut accepted: Vec<String> = Vec::with_capacity(names.len());
        for name in names {
            if !is_env_name(name) {
                return Err(AdapterError::invalid_target("pass-env-name"));
            }
            if !accepted.contains(name) {
                accepted.push(name.clone());
            }
        }
        self.pass_env = accepted;
        Ok(self)
    }

    /// Variable names passed through from the operator's environment.
    pub fn pass_env(&self) -> &[String] {
        &self.pass_env
    }

    /// Executable path or name.
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Argument vector (not a shell string).
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Always false: this crate never launches through a shell.
    pub const fn uses_shell(&self) -> bool {
        false
    }

    /// Always false: parent environment is not inherited in full.
    pub const fn inherits_full_environment(&self) -> bool {
        false
    }

    /// Keys copied from the current process after `env_clear`.
    pub fn explicit_env_allowlist(&self) -> &'static [&'static str] {
        STDIO_ENV_ALLOWLIST
    }

    /// Construct a Tokio command from executable + argv.
    pub fn to_tokio_command(&self) -> Command {
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args);
        cmd.env_clear();
        let passed = self.pass_env.iter().map(String::as_str);
        for key in STDIO_ENV_ALLOWLIST.iter().copied().chain(passed) {
            if let Some(value) = std::env::var_os(key) {
                cmd.env(key, value);
            }
        }
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.kill_on_drop(true);
        cmd
    }
}

fn is_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    name.len() <= MAX_PASS_ENV_NAME
        && (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn looks_like_shell_wrapper(program: &str) -> bool {
    let name = std::path::Path::new(program)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(program)
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "cmd"
            | "cmd.exe"
            | "command.com"
            | "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
            | "sh"
            | "bash"
            | "zsh"
            | "fish"
            | "csh"
            | "dash"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_named_variables_are_passed_through() {
        let launch = StdioLaunch::new("mcp-server", Vec::new())
            .expect("launch")
            .with_pass_env(&["PATH".to_owned(), "PATH".to_owned()])
            .expect("valid names");
        assert_eq!(launch.pass_env(), ["PATH"]);
        let cmd = launch.to_tokio_command();
        let envs: Vec<_> = cmd.as_std().get_envs().collect();
        let path = std::env::var_os("PATH").expect("test runner has PATH");
        assert!(envs
            .iter()
            .any(|(k, v)| *k == "PATH" && v.map(|v| v == path.as_os_str()) == Some(true)));
        // Nothing the operator did not name leaks through, e.g. HOME.
        assert!(!envs.iter().any(|(k, _)| *k == "HOME"));
    }

    #[test]
    fn pass_env_names_are_validated() {
        let launch = || StdioLaunch::new("mcp-server", Vec::new()).expect("launch");
        for bad in ["", "A=B", "1ABC", "A B", "PATH;id", "A-B", &"A".repeat(65)] {
            assert!(
                launch().with_pass_env(&[bad.to_owned()]).is_err(),
                "{bad:?} must be refused"
            );
        }
        let many: Vec<String> = (0..=MAX_PASS_ENV).map(|i| format!("V{i}")).collect();
        assert!(launch().with_pass_env(&many).is_err());
        assert!(launch()
            .with_pass_env(&["_X1".to_owned(), "api_key".to_owned()])
            .is_ok());
    }

    #[test]
    fn argv_is_program_plus_args_without_shell() {
        let launch = StdioLaunch::new(
            "C:/tools/mcp-server.exe",
            vec!["--flag".to_owned(), "value".to_owned()],
        )
        .expect("valid launch");
        assert_eq!(launch.program(), "C:/tools/mcp-server.exe");
        assert_eq!(launch.args(), ["--flag", "value"]);
        assert!(!launch.uses_shell());
        assert!(!launch.inherits_full_environment());

        let cmd = launch.to_tokio_command();
        let std = cmd.as_std();
        assert_eq!(std.get_program(), "C:/tools/mcp-server.exe");
        let args: Vec<_> = std
            .get_args()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args, ["--flag", "value"]);
    }

    #[test]
    fn synthetic_trace_path_is_on_the_explicit_env_allowlist() {
        let launch = StdioLaunch::new("synthetic-mcp", Vec::<String>::new()).expect("launch");
        assert!(launch
            .explicit_env_allowlist()
            .contains(&"SYNTHETIC_MCP_TRACE_PATH"));
        assert!(!launch.inherits_full_environment());
    }

    #[test]
    fn empty_program_is_rejected() {
        let err = StdioLaunch::new("", Vec::<String>::new()).expect_err("empty");
        assert!(matches!(err, AdapterError::InvalidTarget { .. }));
    }

    #[test]
    fn shell_wrappers_are_rejected() {
        for program in ["cmd.exe", "powershell", "bash", "/bin/sh"] {
            let err = StdioLaunch::new(program, Vec::<String>::new()).expect_err(program);
            match err {
                AdapterError::InvalidTarget { kind } => assert_eq!(kind, "shell-program"),
                other => panic!("unexpected error: {other}"),
            }
        }
    }
}
