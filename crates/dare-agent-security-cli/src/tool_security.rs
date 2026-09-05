//! `dare-agent-security validate tool-security` (Cycle 014).
//!
//! Bounded, local, offline validation of one tool-poisoning or tool-misuse
//! scenario.
//!
//! The flag surface is deliberately narrow. There is no `--url`, `--endpoint`,
//! `--api-key`, `--token`, `--provider`, `--remote`, `--command` or live-MCP
//! option, because Cycle 014 has no remote, provider or tool-execution path for
//! such a flag to reach. Modes are the three approved local ones, and a
//! structured tool request is observed, never dispatched.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use dare_tool_security::canonical::bind;
use dare_tool_security::corpus::{builtin_corpus_root, load_corpus, ToolCorpus};
use dare_tool_security::evidence_bridge::{build_evidence, SYNTHETIC_TARGET_ID};
use dare_tool_security::harness::{ToolHarnessAdapter, ToolHarnessMode};
use dare_tool_security::local_synthetic::ToolLocalSyntheticAdapter;
use dare_tool_security::model::ToolFamily;
use dare_tool_security::model::{ToolCorpusEntry, ToolLabSpec, ToolSecurityScenario};
use dare_tool_security::replay::ToolReplayAdapter;
use dare_tool_security::result::{run_scenario, ToolSecurityResult};
use dare_tool_security::schema::{enforce_document_size, validate_scenario_document};
use dare_tool_security::simulated::ToolSimulatedAdapter;
use dare_tool_security::source::{MisuseSurface, ScenarioClass, ToolSurfaceArea};
use dare_tool_security::trials::ToolTrialPlan;
use dare_tool_security::{ToolSecurityError, Verdict};
use serde_json::Value;
use time::OffsetDateTime;

use crate::ci_output::validate_output_dir;
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

/// Approved local modes. There is no remote, provider or live-MCP variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ToolSecurityModeArg {
    /// Evaluate a sanitized local trace without invoking a tool or server.
    Replay,
    /// Deterministic corpus-derived observations.
    Simulated,
    /// Controlled local synthetic execution through the Cycle 009 substrate.
    LocalSynthetic,
}

impl From<ToolSecurityModeArg> for ToolHarnessMode {
    fn from(value: ToolSecurityModeArg) -> Self {
        match value {
            ToolSecurityModeArg::Replay => Self::Replay,
            ToolSecurityModeArg::Simulated => Self::Simulated,
            ToolSecurityModeArg::LocalSynthetic => Self::LocalSynthetic,
        }
    }
}

/// `validate tool-security` options.
#[derive(Debug, Args)]
#[command(after_help = TOOL_SECURITY_AFTER_HELP)]
pub struct ToolSecurityArgs {
    /// Scenario file path, or a built-in scenario id such as `TOOL-LAB-001`.
    #[arg(long, value_name = "PATH-OR-ID")]
    pub scenario: String,

    /// Execution mode. All modes are local and offline.
    #[arg(long, value_enum, default_value = "simulated")]
    pub mode: ToolSecurityModeArg,

    /// Sanitized local tool trace. Replay mode only.
    #[arg(long, value_name = "PATH")]
    pub trace: Option<PathBuf>,

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

pub const TOOL_SECURITY_AFTER_HELP: &str = "\
Exit codes (`validate tool-security`):
  0  no tool-security invariant violation was observed for the tested vectors
  1  harness or environment error
  2  a deterministic invariant violation was observed, or evidence was inconclusive
  3  usage error or safety refusal

Modes are local and offline: replay, simulated, local-synthetic.
This capability has no remote target, no MCP client, no provider adapter and no
credential flag. Structured tool requests are observed, never dispatched: no
delete, send, payment or external fetch is performed by this command.
A PASS is scoped to the tested vectors under the recorded conditions, and is
never a claim that the tools are secure, safe or immune.
";

fn scenarios_root() -> PathBuf {
    PathBuf::from("fixtures/tool-security/scenarios")
}

/// Resolve `--scenario` as a built-in id or a file path.
fn load_scenario(spec: &str) -> Result<ToolSecurityScenario, ToolSecurityError> {
    let path = if spec.ends_with(".json") || spec.contains('/') || spec.contains('\\') {
        PathBuf::from(spec)
    } else {
        // Built-in id. The pattern keeps this from becoming a path expression.
        if !spec
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(ToolSecurityError::invalid(
                "scenario id must be uppercase alphanumeric with dashes",
            ));
        }
        scenarios_root().join(format!("{spec}.json"))
    };

    let raw = fs::read(&path).map_err(|err| {
        ToolSecurityError::invalid(format!("scenario unavailable ({}): {err}", path.display()))
    })?;
    enforce_document_size(&raw, "scenario")?;
    let value: Value = serde_json::from_slice(&raw)
        .map_err(|err| ToolSecurityError::schema(format!("scenario is not valid JSON: {err}")))?;
    validate_scenario_document(&value)?;
    serde_json::from_value(value).map_err(Into::into)
}

fn load_corpus_for(args: &ToolSecurityArgs) -> Result<ToolCorpus, ToolSecurityError> {
    let root = args.corpus.clone().unwrap_or_else(builtin_corpus_root);
    load_corpus(&root)
}

fn build_adapter(
    args: &ToolSecurityArgs,
    scenario: &ToolSecurityScenario,
) -> Result<Box<dyn ToolHarnessAdapter>, ToolSecurityError> {
    let mode: ToolHarnessMode = args.mode.into();

    if mode != ToolHarnessMode::Replay && args.trace.is_some() {
        return Err(ToolSecurityError::invalid(
            "--trace is only valid with --mode replay",
        ));
    }

    match mode {
        ToolHarnessMode::Replay => {
            let path = args
                .trace
                .as_ref()
                .ok_or_else(|| ToolSecurityError::invalid("--mode replay requires --trace"))?;
            let root = path.parent().unwrap_or(Path::new(".")).to_path_buf();
            let name = path
                .file_name()
                .map(PathBuf::from)
                .ok_or_else(|| ToolSecurityError::invalid("trace path has no file name"))?;
            let adapter = ToolReplayAdapter::load(&root, &name)?;
            adapter.bind_scenario(&scenario.id)?;
            Ok(Box::new(adapter))
        }
        ToolHarnessMode::Simulated => Ok(Box::new(ToolSimulatedAdapter::new(lab_spec(scenario)?))),
        ToolHarnessMode::LocalSynthetic => Ok(Box::new(ToolLocalSyntheticAdapter::new(
            lab_spec(scenario)?,
            SYNTHETIC_TARGET_ID,
            scenario.trials.count,
        ))),
    }
}

fn lab_spec(scenario: &ToolSecurityScenario) -> Result<ToolLabSpec, ToolSecurityError> {
    scenario.lab.clone().ok_or_else(|| {
        ToolSecurityError::invalid(
            "simulated and local-synthetic modes require the scenario to declare a lab \
             reference behavior",
        )
    })
}

/// Which tool-security surfaces this scenario exercised.
///
/// Poisoning and misuse are separate dimensions, and a scenario tests one of
/// them. The other is reported as not tested rather than quietly as passing.
fn surface_states(result: &ToolSecurityResult) -> (&'static str, &'static str) {
    match result.class {
        ScenarioClass::Poisoning => ("TESTED", "NOT TESTED"),
        ScenarioClass::Misuse => ("NOT TESTED", "TESTED"),
    }
}

/// The typed family this run exercised.
///
/// Decoding the recorded token back into the closed taxonomy keeps surface
/// reporting on exact typed mappings. Matching family names by substring is how
/// a description-poisoning run gets mislabelled as untested.
fn family_of(result: &ToolSecurityResult) -> Option<ToolFamily> {
    serde_json::from_value(Value::String(result.family.clone())).ok()
}

/// State of one poisoning surface area for this run.
///
/// "not applicable" and "not tested" are different answers: a misuse scenario
/// has no poisoning surface to exercise, while a poisoning scenario aimed at
/// output leaves the description surface untested but applicable.
fn poisoning_surface(result: &ToolSecurityResult, area: ToolSurfaceArea) -> &'static str {
    match family_of(result) {
        Some(ToolFamily::Poisoning(family)) if family.surface_area() == area => "TESTED",
        Some(ToolFamily::Poisoning(_)) => "NOT TESTED",
        _ => "NOT APPLICABLE",
    }
}

/// State of one misuse surface for this run.
fn misuse_surface(result: &ToolSecurityResult, surface: MisuseSurface) -> &'static str {
    match family_of(result) {
        Some(ToolFamily::Misuse(family)) if family.misuse_surface() == surface => "TESTED",
        Some(ToolFamily::Misuse(_)) => "NOT TESTED",
        _ => "NOT APPLICABLE",
    }
}

/// Render the operator summary with bounded claim wording.
fn render_summary(result: &ToolSecurityResult) -> String {
    let (poisoning_state, misuse_state) = surface_states(result);
    let violations = result.violations().len();
    let inconclusive = result
        .trials
        .iter()
        .filter(|trial| trial.verdict == Verdict::Inconclusive)
        .count();

    format!(
        "# DARE Tool Security Validation\n\n\
         | Field | Value |\n\
         |---|---|\n\
         | Scenario | {scenario} |\n\
         | Corpus vector | {corpus} |\n\
         | Property | {property} |\n\
         | Invariant | {invariant} |\n\
         | Source boundary | {source} ({trust}) |\n\
         | Tool surface | {surface} |\n\
         | Mode | {mode} |\n\
         | Synthetic observations | {synthetic} |\n\n\
         ## Surfaces\n\n\
         | Surface | State |\n\
         |---|---|\n\
         | TOOL_POISONING | {poisoning_state} |\n\
         | TOOL_MISUSE | {misuse_state} |\n\
         | Poisoning: description | {description} |\n\
         | Poisoning: input schema | {schema} |\n\
         | Poisoning: annotations | {annotations} |\n\
         | Poisoning: metadata | {metadata} |\n\
         | Poisoning: output | {output} |\n\
         | Misuse: selection | {selection} |\n\
         | Misuse: arguments | {arguments} |\n\
         | Misuse: chain | {chain} |\n\
         | Misuse: invocation | {invocation} |\n\
         | Misuse: output escalation | {escalation} |\n\n\
         ## Counts\n\n\
         | Measure | Value |\n\
         |---|---|\n\
         | Scenarios | 1 |\n\
         | Trials planned | {planned} |\n\
         | Trials executed | {executed} |\n\
         | Tool requests observed | {requests} |\n\
         | Maximum chain depth observed | {depth} |\n\
         | Violations observed | {violations} |\n\
         | Inconclusive trials | {inconclusive} |\n\
         | State changes | 0 |\n\
         | External egress bytes | 0 |\n\
         | Stop reason | {stop} |\n\
         | Verdict | {verdict} |\n\n\
         {claim}\n\n\
         Scope: this run exercised a finite local corpus under the recorded conditions. \
         Structured tool requests were observed and never dispatched. It does not establish \
         that the tool surface resists poisoning or misuse in general, and no result here \
         should be read as a claim of universal tool security.\n",
        scenario = result.scenario_id,
        corpus = result.corpus_id.as_deref().unwrap_or("(none)"),
        property = result.property_id,
        invariant = result.invariant.as_str(),
        source = result.source_kind.as_str(),
        trust = result.source_trust.as_str(),
        surface = result.surface_id,
        mode = result.mode.as_str(),
        synthetic = if result.synthetic { "yes" } else { "no" },
        poisoning_state = poisoning_state,
        misuse_state = misuse_state,
        description = poisoning_surface(result, ToolSurfaceArea::Description),
        schema = poisoning_surface(result, ToolSurfaceArea::InputSchema),
        annotations = poisoning_surface(result, ToolSurfaceArea::Annotations),
        metadata = poisoning_surface(result, ToolSurfaceArea::Metadata),
        output = poisoning_surface(result, ToolSurfaceArea::Output),
        selection = misuse_surface(result, MisuseSurface::Selection),
        arguments = misuse_surface(result, MisuseSurface::Arguments),
        chain = misuse_surface(result, MisuseSurface::Chain),
        invocation = misuse_surface(result, MisuseSurface::Invocation),
        escalation = misuse_surface(result, MisuseSurface::OutputEscalation),
        planned = result.trials_planned,
        executed = result.trials_executed,
        requests = result.tool_requests(),
        depth = result
            .max_chain_depth()
            .map(|depth| depth.to_string())
            .unwrap_or_else(|| "none observed".to_owned()),
        violations = violations,
        inconclusive = inconclusive,
        stop = result.stop_reason.as_str(),
        verdict = result.verdict.as_str(),
        claim = result.bounded_claim(),
    )
}

pub fn run_tool_security(args: ToolSecurityArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(error) if error.is_refusal() => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error @ (ToolSecurityError::Invalid(_) | ToolSecurityError::Schema(_))) => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error) => {
            eprintln!("{error}");
            SCANNER_ERROR
        }
    }
}

fn run_inner(args: ToolSecurityArgs) -> Result<i32, ToolSecurityError> {
    let scenario = load_scenario(&args.scenario)?;

    // The corpus is loaded whenever the scenario names a vector, in every mode.
    // A poisoned or substituted vector must be refused even when the run itself
    // would have replayed a trace.
    let entry: Option<ToolCorpusEntry> = match scenario.vector.as_ref() {
        Some(vector) => {
            let corpus = load_corpus_for(&args)?;
            Some(corpus.require(&vector.corpus_id)?.clone())
        }
        None => None,
    };

    // Refuse a substituted objective, policy, tool surface or vector before
    // anything is observed.
    let binding = bind(&scenario)?;

    let plan = ToolTrialPlan::from_scenario(&scenario)?.with_trial_override(args.trials)?;
    let adapter = build_adapter(&args, &scenario)?;
    let result = run_scenario(&scenario, entry.as_ref(), adapter.as_ref(), plan)?;

    let evidence = build_evidence(
        &scenario,
        entry.as_ref(),
        &binding,
        &result,
        OffsetDateTime::now_utc(),
    )?;

    validate_output_dir(&args.output_dir).map_err(ToolSecurityError::invalid)?;
    fs::create_dir_all(&args.output_dir)?;

    write_json(&args.output_dir.join("tool-security-result.json"), &result)?;
    write_json(
        &args.output_dir.join("tool-security-trials.json"),
        &result.trials,
    )?;
    write_json(
        &args.output_dir.join("tool-security-evidence.json"),
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

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), ToolSecurityError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    assert_bytes_are_secret_safe(&bytes)?;
    fs::write(path, bytes)?;
    Ok(())
}

/// Refuse to write an artifact that carries a canary or credential.
fn assert_bytes_are_secret_safe(bytes: &[u8]) -> Result<(), ToolSecurityError> {
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
            return Err(ToolSecurityError::refusal(
                "refusing to write an artifact containing sensitive content",
            ));
        }
    }
    Ok(())
}

/// Refuse to write a summary that overstates what was validated.
fn assert_summary_is_bounded(summary: &str) -> Result<(), ToolSecurityError> {
    let lowered = summary.to_lowercase();
    for forbidden in [
        "tool secure",
        "tools are secure",
        "safe tools",
        "immune",
        "fully protected",
        "guaranteed secure",
        "cannot be poisoned",
        "cannot be misused",
    ] {
        if lowered.contains(forbidden) {
            return Err(ToolSecurityError::refusal(format!(
                "refusing to write an unbounded security claim: {forbidden}"
            )));
        }
    }
    assert_bytes_are_secret_safe(summary.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser as _};

    #[derive(Debug, clap::Parser)]
    struct Wrapper {
        #[command(flatten)]
        args: ToolSecurityArgs,
    }

    fn long_flags() -> Vec<String> {
        Wrapper::command()
            .get_arguments()
            .filter_map(|arg| arg.get_long().map(str::to_owned))
            .collect()
    }

    #[test]
    fn the_flag_surface_is_exactly_the_approved_one() {
        let mut flags = long_flags();
        flags.sort();
        assert_eq!(
            flags,
            [
                "corpus",
                "json",
                "mode",
                "output-dir",
                "scenario",
                "trace",
                "trials"
            ]
        );
    }

    #[test]
    fn no_remote_credential_or_command_flag_exists() {
        // Exact whole-flag comparison, not a substring search: `--provider`
        // must be absent, and a legitimate flag must never trip this by
        // containing a forbidden word.
        let flags = long_flags();
        for forbidden in [
            "url",
            "endpoint",
            "api-key",
            "apikey",
            "token",
            "provider",
            "remote",
            "command",
            "server",
            "mcp",
            "mcp-server",
            "host",
            "base-url",
            "credential",
            "auth",
            "live",
        ] {
            assert!(
                !flags.iter().any(|flag| flag == forbidden),
                "`--{forbidden}` must not exist on this capability"
            );
        }
    }

    #[test]
    fn only_the_three_offline_modes_are_selectable() {
        let variants: Vec<&str> = ToolSecurityModeArg::value_variants()
            .iter()
            .filter_map(|mode| mode.to_possible_value())
            .map(|value| value.get_name().to_owned())
            .map(|name| Box::leak(name.into_boxed_str()) as &str)
            .collect();
        assert_eq!(variants, ["replay", "simulated", "local-synthetic"]);
    }

    #[test]
    fn the_trial_flag_cannot_exceed_the_approved_hard_maximum() {
        assert!(Wrapper::try_parse_from([
            "x",
            "--scenario",
            "TOOL-LAB-001",
            "--output-dir",
            "out",
            "--trials",
            "10"
        ])
        .is_ok());
        assert!(Wrapper::try_parse_from([
            "x",
            "--scenario",
            "TOOL-LAB-001",
            "--output-dir",
            "out",
            "--trials",
            "11"
        ])
        .is_err());
        assert!(Wrapper::try_parse_from([
            "x",
            "--scenario",
            "TOOL-LAB-001",
            "--output-dir",
            "out",
            "--trials",
            "0"
        ])
        .is_err());
    }

    #[test]
    fn the_help_text_states_the_no_dispatch_and_bounded_claim_facts() {
        assert!(TOOL_SECURITY_AFTER_HELP.contains("observed, never dispatched"));
        assert!(TOOL_SECURITY_AFTER_HELP.contains("no MCP client"));
        assert!(TOOL_SECURITY_AFTER_HELP.contains("never a claim that the tools are secure"));
    }

    #[test]
    fn an_unbounded_summary_is_refused_before_it_is_written() {
        for claim in [
            "The tools are secure.",
            "Safe tools confirmed.",
            "The agent is immune to tool poisoning.",
            "Fully protected.",
            "Guaranteed secure.",
        ] {
            assert!(
                assert_summary_is_bounded(claim).is_err(),
                "must refuse: {claim}"
            );
        }
        assert!(assert_summary_is_bounded(
            "No tool-security invariant violation was observed for the tested vectors under \
             the recorded conditions."
        )
        .is_ok());
    }

    #[test]
    fn an_artifact_carrying_a_canary_or_credential_is_refused() {
        assert!(assert_bytes_are_secret_safe(b"DARE-SYNTHETIC-CANARY-TOOL01").is_err());
        assert!(assert_bytes_are_secret_safe(b"sk-live-abcdef").is_err());
        assert!(assert_bytes_are_secret_safe(b"Bearer ya29.token").is_err());
        assert!(assert_bytes_are_secret_safe(b"Ticket 42 is open.").is_ok());
    }

    #[test]
    fn a_trace_is_rejected_outside_replay_mode() {
        let scenario: ToolSecurityScenario = serde_json::from_str(include_str!(
            "../../../fixtures/tool-security/scenarios/TOOL-LAB-001.json"
        ))
        .expect("scenario fixture decodes");
        let args = ToolSecurityArgs {
            scenario: "TOOL-LAB-001".to_owned(),
            mode: ToolSecurityModeArg::Simulated,
            trace: Some(PathBuf::from("some-trace.json")),
            corpus: None,
            trials: None,
            output_dir: PathBuf::from("out"),
            json: false,
        };
        let Err(err) = build_adapter(&args, &scenario) else {
            panic!("a trace outside replay mode must be rejected");
        };
        assert!(err.to_string().contains("--trace is only valid"));
    }
}
