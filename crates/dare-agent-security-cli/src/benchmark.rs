//! `dare-agent-security validate benchmark` — offline corpus methodology runner.

use std::fs;
use std::path::PathBuf;

use clap::Args;
use dare_benchmark::{
    aggregate_records, build_benchmark_run, builtin_policy, digest_value, load_corpus_file,
    run_corpus_offline, RunnerMode, RunnerOptions,
};
use dare_coverage::{builtin_profile, profile_digest_sha256, REGISTRY_JSON};
use dare_mcp_discovery::sanitize_stream;

use crate::ci_output::{assert_summary_secret_safe, validate_output_dir};
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

#[derive(Debug, Args)]
pub struct BenchmarkArgs {
    /// Path to a Corpus Manifest JSON file.
    #[arg(long, value_name = "PATH")]
    pub corpus: PathBuf,

    #[arg(long, value_name = "PATH")]
    pub output_dir: Option<PathBuf>,

    /// Runner mode. AUTHORIZED_DYNAMIC is refused unless policy + ROE allow it.
    #[arg(long, value_enum, default_value = "local-passive")]
    pub mode: BenchmarkModeArg,

    /// Explicit Rules-of-Engagement acknowledgment for AUTHORIZED_DYNAMIC only.
    #[arg(long, default_value_t = false)]
    pub authorized_dynamic_roe: bool,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum BenchmarkModeArg {
    Static,
    LocalPassive,
    AuthorizedDynamic,
}

impl From<BenchmarkModeArg> for RunnerMode {
    fn from(value: BenchmarkModeArg) -> Self {
        match value {
            BenchmarkModeArg::Static => RunnerMode::Static,
            BenchmarkModeArg::LocalPassive => RunnerMode::LocalPassive,
            BenchmarkModeArg::AuthorizedDynamic => RunnerMode::AuthorizedDynamic,
        }
    }
}

pub fn run_benchmark(args: BenchmarkArgs) -> i32 {
    match run_benchmark_inner(args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{}", sanitize_stream(&message));
            if message.contains("usage") || message.contains("Safety refusal") {
                UNSUPPORTED_TARGET
            } else {
                SCANNER_ERROR
            }
        }
    }
}

fn run_benchmark_inner(args: BenchmarkArgs) -> Result<i32, String> {
    let manifest = load_corpus_file(&args.corpus).map_err(|e| e.to_string())?;
    let policy = builtin_policy().map_err(|e| e.to_string())?;
    let profile = builtin_profile().map_err(|e| e.to_string())?;
    let profile_digest = profile_digest_sha256(&profile).map_err(|e| e.to_string())?;
    let registry_value: serde_json::Value =
        serde_json::from_str(REGISTRY_JSON).map_err(|e| e.to_string())?;
    let registry_digest = digest_value(&registry_value).map_err(|e| e.to_string())?;
    let mode = RunnerMode::from(args.mode);
    let run = build_benchmark_run(
        "cli-benchmark-run",
        &manifest,
        &policy,
        &profile.id,
        &profile.version,
        &profile_digest,
        "1.0.0",
        &registry_digest,
        "local-dev-unpinned",
        mode,
    )
    .map_err(|e| e.to_string())?;
    let options = RunnerOptions {
        mode,
        authorized_dynamic_roe: args.authorized_dynamic_roe,
    };
    let records =
        run_corpus_offline(&manifest, &run, &policy, &options).map_err(|e| e.to_string())?;
    let aggregate = aggregate_records(&manifest, &records, &policy);

    if args.json {
        let body = serde_json::json!({
            "benchmark_run": run,
            "records": records,
            "aggregate": aggregate,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&body).map_err(|e| e.to_string())?
        );
    }

    if let Some(output_dir) = args.output_dir.as_ref() {
        validate_output_dir(output_dir)?;
        fs::create_dir_all(output_dir).map_err(|e| e.to_string())?;
        fs::write(
            output_dir.join("benchmark-run.json"),
            serde_json::to_vec_pretty(&run).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        fs::write(
            output_dir.join("aggregate.json"),
            serde_json::to_vec_pretty(&aggregate).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let records_dir = output_dir.join("records");
        fs::create_dir_all(&records_dir).map_err(|e| e.to_string())?;
        for record in &records {
            let path = records_dir.join(format!("{}.json", record.target.id));
            fs::write(
                &path,
                serde_json::to_vec_pretty(record).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        }
        let summary = format!(
            "# DARE Benchmark\n\nCorpus: {}@{}\nTargets: {}\nPrevalence-eligible: {}\nFAIL findings: {}\nAffected targets (FAIL): {}\n\n{}\n",
            aggregate.corpus_id,
            aggregate.corpus_version,
            aggregate.target_count,
            aggregate.prevalence_eligible_targets,
            aggregate.finding_count_fail,
            aggregate.affected_target_count_fail,
            aggregate.disclaimer
        );
        assert_summary_secret_safe(&summary)?;
        fs::write(output_dir.join("summary.md"), summary).map_err(|e| e.to_string())?;
    }

    if records.is_empty() {
        Ok(PARTIAL)
    } else {
        Ok(SUCCESS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_cli_runs_pilot_offline() {
        let dir = tempfile::tempdir().unwrap();
        let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../benchmark/corpus/pilot-methodology-v1/corpus-manifest.json");
        let code = run_benchmark(BenchmarkArgs {
            corpus,
            output_dir: Some(dir.path().to_path_buf()),
            mode: BenchmarkModeArg::LocalPassive,
            authorized_dynamic_roe: false,
            json: false,
        });
        assert_eq!(code, SUCCESS);
        assert!(dir.path().join("aggregate.json").is_file());
        assert!(dir.path().join("benchmark-run.json").is_file());
    }
}
