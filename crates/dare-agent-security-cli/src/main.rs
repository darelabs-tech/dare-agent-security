//! `dare-agent-security` CLI binary.

use std::process::ExitCode;

use clap::{error::ErrorKind, Parser};
use dare_agent_security::adversarial::run_adversarial;
use dare_agent_security::args::{Cli, Command, ValidateSubcommand};
use dare_agent_security::attack_graph::run_attack_graph;
use dare_agent_security::benchmark::run_benchmark;
use dare_agent_security::ci::run_ci;
use dare_agent_security::coaz_integrity::run_coaz_integrity;
use dare_agent_security::continuous::run_continuous;
use dare_agent_security::coverage::run_coverage;
use dare_agent_security::discover::run_discover;
use dare_agent_security::exit_code::{SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};
use dare_agent_security::product::{run_assess, run_doctor_cmd, run_init, run_report};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    match Cli::try_parse() {
        Ok(cli) => match cli.command {
            Command::Init(args) => ExitCode::from(run_init(args) as u8),
            Command::Assess(args) => ExitCode::from(run_assess(args) as u8),
            Command::Report(args) => ExitCode::from(run_report(args) as u8),
            Command::Doctor(args) => ExitCode::from(run_doctor_cmd(args) as u8),
            Command::Discover(args) => ExitCode::from(run_discover(args).await as u8),
            Command::Validate { command } => match command {
                ValidateSubcommand::CoazIntegrity(args) => {
                    ExitCode::from(run_coaz_integrity(args) as u8)
                }
                ValidateSubcommand::Coverage(args) => ExitCode::from(run_coverage(args) as u8),
                ValidateSubcommand::Benchmark(args) => ExitCode::from(run_benchmark(args) as u8),
                ValidateSubcommand::AttackGraph(args) => {
                    ExitCode::from(run_attack_graph(args) as u8)
                }
                ValidateSubcommand::Adversarial(args) => {
                    ExitCode::from(run_adversarial(args) as u8)
                }
                ValidateSubcommand::Continuous(args) => ExitCode::from(run_continuous(args) as u8),
            },
            Command::Ci { command } => ExitCode::from(run_ci(command) as u8),
        },
        Err(err) => {
            let _ = err.print();
            ExitCode::from(clap_exit_code(&err) as u8)
        }
    }
}

fn clap_exit_code(err: &clap::Error) -> i32 {
    match err.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => SUCCESS,
        ErrorKind::ArgumentConflict
        | ErrorKind::MissingRequiredArgument
        | ErrorKind::MissingSubcommand
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => UNSUPPORTED_TARGET,
        _ => {
            if err.use_stderr() {
                SCANNER_ERROR
            } else {
                SUCCESS
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use dare_coaz_integrity::{evidence_kernel_name, CRATE_NAME as INTEGRITY_CRATE_NAME};
    use dare_mcp_discovery::{evidence_kernel_name as discovery_kernel, CLI_BIN_NAME, CRATE_NAME};

    #[test]
    fn cli_binary_depends_on_discovery() {
        assert_eq!(env!("CARGO_PKG_NAME"), "dare-agent-security");
        assert_eq!(CLI_BIN_NAME, "dare-agent-security");
        assert_eq!(CRATE_NAME, "dare-mcp-discovery");
        assert_eq!(discovery_kernel(), "dare-security-evidence");
    }

    #[test]
    fn cli_binary_depends_on_coaz_integrity() {
        assert_eq!(INTEGRITY_CRATE_NAME, "dare-coaz-integrity");
        assert_eq!(evidence_kernel_name(), "dare-security-evidence");
    }
}
