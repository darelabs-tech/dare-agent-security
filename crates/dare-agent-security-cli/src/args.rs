//! Clap argument surface for `dare-agent-security`.

use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

use crate::exit_code::AFTER_HELP;

/// DARE Agent Security CLI.
#[derive(Debug, Parser)]
#[command(
    name = "dare-agent-security",
    version,
    about = "Passive MCP discovery and security baseline scanner",
    after_help = AFTER_HELP,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Supported CLI commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Discover an explicit MCP target without invoking tools or reading contents.
    Discover(DiscoverArgs),
}

/// `dare-agent-security discover` options.
#[derive(Debug, Args)]
#[command(after_help = AFTER_HELP)]
pub struct DiscoverArgs {
    /// Discover a local stdio MCP server. The executable and argv follow `--`.
    #[arg(long, conflicts_with = "url")]
    pub stdio: bool,

    /// Discover a Streamable HTTP MCP server. HTTPS only; credentials in the URL are refused.
    #[arg(long, value_name = "HTTPS-URL", conflicts_with = "stdio")]
    pub url: Option<String>,

    /// Write canonical Inventory v1 JSON only to stdout. Diagnostics go to stderr.
    #[arg(long)]
    pub json: bool,

    /// Operator-safe target identifier used in the inventory envelope.
    #[arg(long, value_name = "SAFE-ID")]
    pub target_id: Option<String>,

    /// Overall discovery timeout (`30`, `30s`, `5m`, `1h`, or `500ms`).
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,

    /// Maximum list pages fetched per catalog.
    #[arg(long, value_name = "N")]
    pub max_pages: Option<usize>,

    /// Maximum items retained per catalog.
    #[arg(long, value_name = "N")]
    pub max_items: Option<usize>,

    /// Write Cycle 001 baseline evidence JSON files into this directory.
    #[arg(long, value_name = "PATH")]
    pub evidence_dir: Option<PathBuf>,

    /// stdio executable and argv after `--`. Never interpolated by a shell.
    #[arg(last = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

impl DiscoverArgs {
    /// Parse `--timeout` into a duration.
    pub fn parsed_timeout(&self) -> Result<Option<Duration>, String> {
        self.timeout.as_deref().map(parse_duration).transpose()
    }
}

pub(crate) fn parse_duration(raw: &str) -> Result<Duration, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("timeout must not be empty".to_owned());
    }
    if let Some(num) = raw.strip_suffix("ms") {
        let millis: u64 = parse_positive_u64(num.trim(), "timeout")?;
        return Ok(Duration::from_millis(millis));
    }
    let (num, multiplier) = if let Some(num) = raw.strip_suffix('s') {
        (num, 1_u64)
    } else if let Some(num) = raw.strip_suffix('m') {
        (num, 60_u64)
    } else if let Some(num) = raw.strip_suffix('h') {
        (num, 3_600_u64)
    } else {
        (raw, 1_u64)
    };
    let secs = parse_positive_u64(num.trim(), "timeout")?
        .checked_mul(multiplier)
        .ok_or_else(|| "timeout overflow".to_owned())?;
    Ok(Duration::from_secs(secs))
}

fn parse_positive_u64(raw: &str, label: &str) -> Result<u64, String> {
    let value: u64 = raw
        .parse()
        .map_err(|_| format!("{label} must be a positive integer"))?;
    if value == 0 {
        return Err(format!("{label} must be greater than zero"));
    }
    Ok(value)
}
