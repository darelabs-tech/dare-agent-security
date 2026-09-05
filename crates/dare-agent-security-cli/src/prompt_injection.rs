//! `dare-agent-security validate prompt-injection` (Cycle 013).
//!
//! Bounded, local, offline validation of one prompt-injection scenario.
//!
//! The flag surface is deliberately narrow. There is no `--url`, `--endpoint`,
//! `--api-key`, `--token`, `--provider`, `--remote` or arbitrary command string,
//! because Cycle 013 has no remote or provider execution path for those flags to
//! reach. Modes are the three approved local ones.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use dare_prompt_injection::canonical::bind;
use dare_prompt_injection::corpus::{builtin_corpus_root, load_corpus, Corpus};
use dare_prompt_injection::evidence_bridge::build_evidence;
use dare_prompt_injection::harness::{HarnessAdapter, HarnessMode};
use dare_prompt_injection::local_synthetic::LocalSyntheticAdapter;
use dare_prompt_injection::model::PromptInjectionScenario;
use dare_prompt_injection::replay::ReplayAdapter;
use dare_prompt_injection::result::{run_scenario, PromptInjectionResult};
use dare_prompt_injection::schema::{enforce_document_size, validate_scenario_document};
use dare_prompt_injection::simulated::{SimulatedAdapter, SimulationProfile};
use dare_prompt_injection::trials::TrialPlan;
use dare_prompt_injection::{PromptInjectionError, Verdict};
use serde_json::Value;
use time::OffsetDateTime;

use crate::ci_output::validate_output_dir;
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

/// Approved local modes. There is no remote or provider variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PromptInjectionModeArg {
    /// Evaluate a sanitized local transcript without invoking a model.
    Replay,
    /// Deterministic fixture-derived outcomes.
    Simulated,
    /// Controlled local synthetic execution through the Cycle 009 substrate.
    LocalSynthetic,
}

impl From<PromptInjectionModeArg> for HarnessMode {
    fn from(value: PromptInjectionModeArg) -> Self {
        match value {
            PromptInjectionModeArg::Replay => Self::Replay,
            PromptInjectionModeArg::Simulated => Self::Simulated,
            PromptInjectionModeArg::LocalSynthetic => Self::LocalSynthetic,
        }
    }
}

/// `validate prompt-injection` options.
#[derive(Debug, Args)]
#[command(after_help = PROMPT_INJECTION_AFTER_HELP)]
pub struct PromptInjectionArgs {
    /// Scenario file path, or a built-in scenario id such as `PI-LAB-001`.
    #[arg(long, value_name = "PATH-OR-ID")]
    pub scenario: String,

    /// Execution mode. All modes are local and offline.
    #[arg(long, value_enum, default_value = "simulated")]
    pub mode: PromptInjectionModeArg,

    /// Sanitized local transcript. Replay mode only.
    #[arg(long, value_name = "PATH")]
    pub transcript: Option<PathBuf>,

    /// Corpus root override. Root-confined; defaults to the built-in corpus.
    #[arg(long, value_name = "PATH")]
    pub corpus: Option<PathBuf>,

    /// Trial count (1..=10). Cannot exceed the approved hard maximum.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=10))]
    pub trials: Option<u32>,

    /// Directory for the result, trials, evidence and summary artifacts.
    #[arg(long, value_name = "PATH")]
    pub output_dir: PathBuf,

    /// Write the result JSON to stdout. Diagnostics go to stderr.
    #[arg(long)]
    pub json: bool,
}

pub const PROMPT_INJECTION_AFTER_HELP: &str = "\
Exit codes (`validate prompt-injection`):
  0  no invariant violation was observed for the tested vector
  1  harness or environment error
  2  a deterministic invariant violation was observed, or evidence was inconclusive
  3  usage error or safety refusal

Modes are local and offline: replay, simulated, local-synthetic.
This capability has no remote target, no provider adapter and no credential flag.
A PASS is scoped to the tested vector under the recorded conditions,
and is never a claim of universal prompt-injection security.
";

fn scenarios_root() -> PathBuf {
    PathBuf::from("fixtures/prompt-injection/scenarios")
}

/// Resolve `--scenario` as a built-in id or a file path.
fn load_scenario(spec: &str) -> Result<PromptInjectionScenario, PromptInjectionError> {
    let path = if spec.ends_with(".json") || spec.contains('/') || spec.contains('\\') {
        PathBuf::from(spec)
    } else {
        // Built-in id. The pattern keeps this from becoming a path expression.
        if !spec
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(PromptInjectionError::invalid(
                "scenario id must be uppercase alphanumeric with dashes",
            ));
        }
        scenarios_root().join(format!("{spec}.json"))
    };

    let raw = fs::read(&path).map_err(|err| {
        PromptInjectionError::invalid(format!("scenario unavailable ({}): {err}", path.display()))
    })?;
    enforce_document_size(&raw, "scenario")?;
    let value: Value = serde_json::from_slice(&raw).map_err(|err| {
        PromptInjectionError::schema(format!("scenario is not valid JSON: {err}"))
    })?;
    validate_scenario_document(&value)?;
    serde_json::from_value(value).map_err(Into::into)
}

fn load_corpus_for(args: &PromptInjectionArgs) -> Result<Corpus, PromptInjectionError> {
    let root = args.corpus.clone().unwrap_or_else(builtin_corpus_root);
    load_corpus(&root)
}

fn build_adapter(
    args: &PromptInjectionArgs,
    scenario: &PromptInjectionScenario,
) -> Result<Box<dyn HarnessAdapter>, PromptInjectionError> {
    let mode: HarnessMode = args.mode.into();

    if mode != HarnessMode::Replay && args.transcript.is_some() {
        return Err(PromptInjectionError::invalid(
            "--transcript is only valid with --mode replay",
        ));
    }

    match mode {
        HarnessMode::Replay => {
            let path = args.transcript.as_ref().ok_or_else(|| {
                PromptInjectionError::invalid("--mode replay requires --transcript")
            })?;
            let root = path.parent().unwrap_or(Path::new(".")).to_path_buf();
            let name = path
                .file_name()
                .map(PathBuf::from)
                .ok_or_else(|| PromptInjectionError::invalid("transcript path has no file name"))?;
            let adapter = ReplayAdapter::load(&root, &name)?;
            adapter.bind_scenario(&scenario.id)?;
            Ok(Box::new(adapter))
        }
        HarnessMode::Simulated => {
            let profile = lab_profile(scenario)?;
            Ok(Box::new(SimulatedAdapter::new(profile)))
        }
        HarnessMode::LocalSynthetic => {
            let profile = lab_profile(scenario)?;
            Ok(Box::new(LocalSyntheticAdapter::new(
                profile,
                "synthetic-prompt-injection-lab",
                scenario.trials.count,
            )))
        }
    }
}

fn lab_profile(
    scenario: &PromptInjectionScenario,
) -> Result<SimulationProfile, PromptInjectionError> {
    scenario
        .lab
        .as_ref()
        .map(|lab| lab.profile())
        .ok_or_else(|| {
            PromptInjectionError::invalid(
                "simulated and local-synthetic modes require the scenario to declare a lab \
                 reference behavior",
            )
        })
}

/// Render the operator summary with bounded claim wording.
fn render_summary(result: &PromptInjectionResult) -> String {
    let direction = result.direction.as_str();
    let (direct_state, indirect_state) = match result.direction {
        dare_prompt_injection::source::InjectionDirection::Direct => ("TESTED", "NOT TESTED"),
        dare_prompt_injection::source::InjectionDirection::Indirect => ("NOT TESTED", "TESTED"),
    };

    format!(
        "# DARE Prompt Injection Validation\n\n\
         | Field | Value |\n\
         |---|---|\n\
         | Scenario | {} |\n\
         | Corpus vector | {} |\n\
         | Property | {} |\n\
         | Invariant | {} |\n\
         | Source boundary | {} ({}) |\n\
         | DIRECT | {} |\n\
         | INDIRECT | {} |\n\
         | Mode | {} |\n\
         | Synthetic observations | {} |\n\
         | Scenarios | 1 |\n\
         | Trials planned | {} |\n\
         | Trials executed | {} |\n\
         | Violations observed | {} |\n\
         | Inconclusive trials | {} |\n\
         | Stop reason | {} |\n\
         | Verdict | {} |\n\n\
         {}\n\n\
         Scope: this run exercised a finite local corpus under the recorded conditions. \
         It does not establish that the target resists prompt injection in general, and no \
         result here should be read as a claim of universal prompt-injection security.\n",
        result.scenario_id,
        result.corpus_id,
        result.property_id,
        result.invariant.as_str(),
        result.source_kind.as_str(),
        direction,
        direct_state,
        indirect_state,
        result.mode.as_str(),
        if result.synthetic { "yes" } else { "no" },
        result.trials_planned,
        result.trials_executed,
        result
            .trials
            .iter()
            .filter(|trial| trial.verdict == Verdict::Fail)
            .count(),
        result
            .trials
            .iter()
            .filter(|trial| trial.verdict == Verdict::Inconclusive)
            .count(),
        result.stop_reason.as_str(),
        result.verdict.as_str(),
        result.bounded_claim(),
    )
}

pub fn run_prompt_injection(args: PromptInjectionArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(error) if error.is_refusal() => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error @ (PromptInjectionError::Invalid(_) | PromptInjectionError::Schema(_))) => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error) => {
            eprintln!("{error}");
            SCANNER_ERROR
        }
    }
}

fn run_inner(args: PromptInjectionArgs) -> Result<i32, PromptInjectionError> {
    let scenario = load_scenario(&args.scenario)?;
    let corpus = load_corpus_for(&args)?;
    let entry = corpus.require(&scenario.vector.corpus_id)?.clone();

    // Refuse a substituted vector or objective before anything runs.
    let binding = bind(&scenario, &entry)?;

    let plan = TrialPlan::from_scenario(&scenario)?.with_trial_override(args.trials)?;
    let adapter = build_adapter(&args, &scenario)?;
    let result = run_scenario(&scenario, &entry, adapter.as_ref(), plan)?;

    let evidence = build_evidence(
        &scenario,
        &entry,
        &binding,
        &result,
        OffsetDateTime::now_utc(),
    )?;

    validate_output_dir(&args.output_dir).map_err(PromptInjectionError::invalid)?;
    fs::create_dir_all(&args.output_dir)?;

    write_json(
        &args.output_dir.join("prompt-injection-result.json"),
        &result,
    )?;
    write_json(
        &args.output_dir.join("prompt-injection-trials.json"),
        &result.trials,
    )?;
    write_json(
        &args.output_dir.join("prompt-injection-evidence.json"),
        &evidence,
    )?;

    let summary = render_summary(&result);
    assert_summary_is_bounded(&summary)?;
    fs::write(args.output_dir.join("summary.md"), summary.as_bytes())?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(match result.verdict {
        Verdict::Pass => SUCCESS,
        Verdict::Fail | Verdict::Inconclusive => PARTIAL,
        Verdict::Error => SCANNER_ERROR,
    })
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), PromptInjectionError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    assert_bytes_are_secret_safe(&bytes)?;
    fs::write(path, bytes)?;
    Ok(())
}

/// Refuse to write an artifact that carries a canary or credential.
fn assert_bytes_are_secret_safe(bytes: &[u8]) -> Result<(), PromptInjectionError> {
    let text = String::from_utf8_lossy(bytes);
    for marker in [
        "DARE-SYNTHETIC-CANARY-",
        "sk-live-",
        "Bearer ",
        "-----BEGIN",
        "ghp_",
        "xoxb-",
    ] {
        if text.contains(marker) {
            return Err(PromptInjectionError::refusal(
                "refusing to write an artifact containing sensitive content",
            ));
        }
    }
    Ok(())
}

/// Refuse to write a summary that overstates what was validated.
fn assert_summary_is_bounded(summary: &str) -> Result<(), PromptInjectionError> {
    let lowered = summary.to_lowercase();
    for forbidden in [
        "prompt injection secure",
        "immune to prompt injection",
        "immune",
        "fully protected",
        "guaranteed secure",
        "cannot be injected",
    ] {
        if lowered.contains(forbidden) {
            return Err(PromptInjectionError::refusal(format!(
                "refusing to write an unbounded security claim: {forbidden}"
            )));
        }
    }
    assert_bytes_are_secret_safe(summary.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_surface_has_no_remote_or_credential_option() {
        use clap::CommandFactory;

        #[derive(Debug, clap::Parser)]
        struct Wrapper {
            #[command(flatten)]
            args: PromptInjectionArgs,
        }

        let command = Wrapper::command();
        let names: Vec<String> = command
            .get_arguments()
            .map(|arg| arg.get_id().to_string())
            .collect();

        for forbidden in [
            "url",
            "endpoint",
            "api_key",
            "api-key",
            "token",
            "provider",
            "provider_key",
            "remote",
            "host",
            "command",
            "exec",
            "shell",
        ] {
            assert!(
                !names.iter().any(|name| name == forbidden),
                "flag `{forbidden}` must not exist for this capability"
            );
        }

        for expected in [
            "scenario",
            "mode",
            "transcript",
            "corpus",
            "trials",
            "output_dir",
            "json",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "flag `{expected}` is required by the Blueprint"
            );
        }
    }

    #[test]
    fn only_local_modes_are_selectable() {
        let values: Vec<String> = PromptInjectionModeArg::value_variants()
            .iter()
            .filter_map(|variant| variant.to_possible_value())
            .map(|value| value.get_name().to_owned())
            .collect();
        assert_eq!(values, vec!["replay", "simulated", "local-synthetic"]);
        assert!(!values.iter().any(|value| value.contains("remote")));
        assert!(!values.iter().any(|value| value.contains("dynamic")));
    }

    #[test]
    fn trial_count_is_range_checked_by_the_parser() {
        use clap::Parser;

        #[derive(Debug, clap::Parser)]
        struct Wrapper {
            #[command(flatten)]
            args: PromptInjectionArgs,
        }

        let ok = Wrapper::try_parse_from([
            "x",
            "--scenario",
            "PI-LAB-001",
            "--output-dir",
            "out",
            "--trials",
            "10",
        ]);
        assert!(ok.is_ok());

        for bad in ["0", "11", "1000"] {
            let err = Wrapper::try_parse_from([
                "x",
                "--scenario",
                "PI-LAB-001",
                "--output-dir",
                "out",
                "--trials",
                bad,
            ]);
            assert!(err.is_err(), "--trials {bad} must be rejected");
        }
    }

    #[test]
    fn a_scenario_id_cannot_become_a_path_expression() {
        for hostile in [
            "../../etc/passwd",
            "..",
            "pi-lab-001",
            "PI LAB 001",
            "PI-LAB-001;rm",
        ] {
            let result = load_scenario(hostile);
            assert!(result.is_err(), "{hostile} must be refused");
        }
    }

    #[test]
    fn summary_wording_is_bounded_and_refuses_universal_claims() {
        assert!(assert_summary_is_bounded(
            "No invariant violation observed for the tested vectors under the recorded conditions."
        )
        .is_ok());

        for unbounded in [
            "The agent is Prompt Injection Secure.",
            "This target is immune to prompt injection.",
            "The agent is fully protected.",
            "It cannot be injected.",
        ] {
            let err = assert_summary_is_bounded(unbounded).unwrap_err();
            assert!(err.is_refusal(), "{unbounded} must be refused");
        }
    }

    #[test]
    fn artifacts_carrying_a_canary_or_credential_are_refused() {
        for hostile in [
            "value DARE-SYNTHETIC-CANARY-ALPHA1",
            "token sk-live-0123456789",
            "Authorization: Bearer abc",
            "-----BEGIN PRIVATE KEY-----",
        ] {
            assert!(assert_bytes_are_secret_safe(hostile.as_bytes()).is_err());
        }
        assert!(assert_bytes_are_secret_safe(b"{\"verdict\":\"PASS\"}").is_ok());
    }

    #[test]
    fn after_help_documents_the_bounded_scope() {
        assert!(PROMPT_INJECTION_AFTER_HELP.contains("local and offline"));
        assert!(PROMPT_INJECTION_AFTER_HELP.contains("no remote target"));
        assert!(PROMPT_INJECTION_AFTER_HELP.contains("no credential flag"));
        assert!(PROMPT_INJECTION_AFTER_HELP.contains("never a claim of universal"));
    }
}
