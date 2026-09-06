//! `dare-agent-security validate memory-security` (Cycle 016).
//!
//! Bounded, local, offline validation of one memory provenance, trust,
//! isolation, lifecycle or decision-influence scenario.
//!
//! The flag surface is deliberately narrow. There is no `--url`, `--redis`,
//! `--postgres`, `--vector-db`, `--pinecone`, `--qdrant`, `--provider`,
//! `--token`, `--api-key`, `--remote` or `--command` option, because Cycle 016
//! has no store, provider or execution path for such a flag to reach. No
//! environment variable can supply a connection string either: this command
//! reads none. Modes are the three approved local ones, memory is described
//! from fixtures and never written anywhere, and lifecycle is evaluated against
//! logical time declared by the scenario rather than the machine's clock.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use dare_memory_security::canonical::bind;
use dare_memory_security::corpus::{builtin_corpus_root, load_corpus, MemoryCorpus};
use dare_memory_security::evidence_bridge::build_evidence;
use dare_memory_security::harness::{HarnessAdapter, HarnessMode};
use dare_memory_security::local_synthetic::LocalSyntheticAdapter;
use dare_memory_security::model::{MemoryCorpusEntry, MemoryInvariantType, MemorySecurityScenario};
use dare_memory_security::replay::ReplayAdapter;
use dare_memory_security::result::{run_scenario, MemorySecurityResult};
use dare_memory_security::schema::{enforce_document_size, validate_scenario_document};
use dare_memory_security::simulated::SimulatedAdapter;
use dare_memory_security::source::ScenarioClass;
use dare_memory_security::{MemorySecurityError, Verdict};
use serde_json::Value;
use time::OffsetDateTime;

use crate::ci_output::validate_output_dir;
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

/// Approved local modes. There is no remote, provider or live-store variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MemorySecurityModeArg {
    /// Evaluate a sanitized local trace without contacting any store.
    Replay,
    /// Deterministic scenario-derived observations.
    Simulated,
    /// Controlled local synthetic execution through the Cycle 009 substrate.
    LocalSynthetic,
}

impl From<MemorySecurityModeArg> for HarnessMode {
    fn from(value: MemorySecurityModeArg) -> Self {
        match value {
            MemorySecurityModeArg::Replay => Self::Replay,
            MemorySecurityModeArg::Simulated => Self::Simulated,
            MemorySecurityModeArg::LocalSynthetic => Self::LocalSynthetic,
        }
    }
}

/// `validate memory-security` options.
#[derive(Debug, Args)]
#[command(after_help = MEMORY_SECURITY_AFTER_HELP)]
pub struct MemorySecurityArgs {
    /// Scenario file path, or a built-in scenario id such as `MEMORY-LAB-001`.
    #[arg(long, value_name = "PATH-OR-ID")]
    pub scenario: String,

    /// Execution mode. All modes are local and offline.
    #[arg(long, value_enum, default_value = "simulated")]
    pub mode: MemorySecurityModeArg,

    /// Sanitized local memory trace. Replay mode only.
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

pub const MEMORY_SECURITY_AFTER_HELP: &str = "\
Exit codes (`validate memory-security`):
  0  no memory-security invariant violation was observed for the tested vectors
  1  harness or environment error
  2  a deterministic invariant violation was observed, or evidence was inconclusive
  3  usage error or safety refusal

Modes are local and offline: replay, simulated, local-synthetic.
This capability has no memory store, vector database, provider, endpoint or
credential flag, and it reads no connection string from the environment. Memory
is described from local synthetic fixtures and is never persisted: no Redis,
PostgreSQL, Pinecone, Weaviate, Qdrant, SaaS memory service, remote MCP server,
production agent or customer memory is involved, and no state change or
external egress occurs.
Lifecycle is evaluated at the logical time each scenario declares, so a verdict
never depends on the machine's clock.
Retrieval, embedding similarity, vector-store authorization and document-level
isolation are out of scope here and are not implied by any result.
A PASS is scoped to the tested vectors under the recorded conditions, and is
never a claim that memory is secure or that poisoning is impossible.
";

fn scenarios_root() -> PathBuf {
    PathBuf::from("crates/dare-memory-security/tests/fixtures/scenarios")
}

/// Resolve `--scenario` as a built-in id or a file path.
fn load_scenario(spec: &str) -> Result<MemorySecurityScenario, MemorySecurityError> {
    let path = if spec.ends_with(".json") || spec.contains('/') || spec.contains('\\') {
        PathBuf::from(spec)
    } else {
        // Built-in id. The pattern keeps this from becoming a path expression.
        if !spec
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(MemorySecurityError::invalid(
                "scenario id must be uppercase alphanumeric with dashes",
            ));
        }
        scenarios_root().join(format!("{}.json", spec.to_ascii_lowercase()))
    };

    let raw = fs::read(&path).map_err(|err| {
        MemorySecurityError::invalid(format!("scenario unavailable ({}): {err}", path.display()))
    })?;
    enforce_document_size(&raw, "scenario")?;
    let value: Value = serde_json::from_slice(&raw)
        .map_err(|err| MemorySecurityError::schema(format!("scenario is not valid JSON: {err}")))?;
    validate_scenario_document(&value)?;
    let scenario: MemorySecurityScenario = serde_json::from_value(value)?;
    scenario.validate()?;
    Ok(scenario)
}

fn load_corpus_for(args: &MemorySecurityArgs) -> Result<MemoryCorpus, MemorySecurityError> {
    let root = args.corpus.clone().unwrap_or_else(builtin_corpus_root);
    load_corpus(&root)
}

fn build_adapter(
    args: &MemorySecurityArgs,
    scenario: &MemorySecurityScenario,
    trials: u32,
) -> Result<Box<dyn HarnessAdapter>, MemorySecurityError> {
    let mode: HarnessMode = args.mode.into();

    if mode != HarnessMode::Replay && args.trace.is_some() {
        return Err(MemorySecurityError::invalid(
            "--trace is only valid with --mode replay",
        ));
    }

    match mode {
        HarnessMode::Replay => {
            let path = args
                .trace
                .as_ref()
                .ok_or_else(|| MemorySecurityError::invalid("--mode replay requires --trace"))?;
            let adapter = ReplayAdapter::from_path(path)?;
            // Refuse a trace recorded against a different scenario before a
            // single observation is read from it.
            adapter.trace().assert_matches(scenario)?;
            Ok(Box::new(adapter))
        }
        HarnessMode::Simulated => {
            require_lab(scenario)?;
            Ok(Box::new(SimulatedAdapter::new()))
        }
        HarnessMode::LocalSynthetic => {
            require_lab(scenario)?;
            Ok(Box::new(LocalSyntheticAdapter::for_scenario(
                scenario, trials,
            )))
        }
    }
}

/// How many trials a replay source can supply, when the source is bounded.
///
/// Only replay is bounded this way: the staged adapters can produce a trial for
/// any index the plan asks for.
fn available_trials(adapter: &dyn HarnessAdapter) -> Option<u32> {
    (adapter.mode() == HarnessMode::Replay).then(|| adapter.trial_capacity())
}

fn require_lab(scenario: &MemorySecurityScenario) -> Result<(), MemorySecurityError> {
    if scenario.lab.is_none() {
        return Err(MemorySecurityError::invalid(
            "simulated and local-synthetic modes require the scenario to declare a lab \
             reference behavior",
        ));
    }
    Ok(())
}

/// State of one memory-security surface for this run.
///
/// "not tested" and "passed" are different answers. A scenario exercises
/// exactly one surface; the other four are reported as untested rather than
/// quietly counted as holding.
fn surface_state(result: &MemorySecurityResult, surface: ScenarioClass) -> &'static str {
    if result.class == surface {
        "TESTED"
    } else {
        "NOT TESTED"
    }
}

/// Which surface the evaluated invariant belongs to.
fn invariant_surface(invariant: MemoryInvariantType) -> ScenarioClass {
    invariant.surface()
}

/// Render the operator summary with bounded claim wording.
fn render_summary(result: &MemorySecurityResult) -> String {
    let violations = result.violations().len();
    let inconclusive = result
        .trials
        .iter()
        .filter(|trial| trial.verdict == Verdict::Inconclusive)
        .count();

    format!(
        "# DARE Memory and Context Poisoning Validation\n\n\
         | Field | Value |\n\
         |---|---|\n\
         | Scenario | {scenario} |\n\
         | Corpus vector | {corpus} |\n\
         | Property | {property} |\n\
         | Invariant | {invariant} |\n\
         | Invariant surface | {invariant_surface} |\n\
         | Source boundary | {source} ({trust}) |\n\
         | Memory store | {store} |\n\
         | Memory items | {items} |\n\
         | Acting principal | {principal} |\n\
         | Tenant | {tenant} |\n\
         | Namespace | {namespace} |\n\
         | Policy | {policy} |\n\
         | Mode | {mode} |\n\
         | Synthetic observations | {synthetic} |\n\n\
         ## Surfaces\n\n\
         | Surface | State |\n\
         |---|---|\n\
         | PROVENANCE | {provenance} |\n\
         | TRUST_BOUNDARY | {trust_boundary} |\n\
         | TENANT_PRINCIPAL | {tenant_principal} |\n\
         | LIFECYCLE | {lifecycle} |\n\
         | DECISION_INFLUENCE | {decision_influence} |\n\n\
         ## Counts\n\n\
         | Measure | Value |\n\
         |---|---|\n\
         | Scenarios | 1 |\n\
         | Trials planned | {planned} |\n\
         | Trials executed | {executed} |\n\
         | Recalled memory items | {recalls} |\n\
         | Violations observed | {violations} |\n\
         | Inconclusive trials | {inconclusive} |\n\
         | Memory items written | 0 |\n\
         | State changes | 0 |\n\
         | External egress bytes | 0 |\n\
         | Stop reason | {stop} |\n\
         | Verdict | {verdict} |\n\n\
         {claim}\n\n\
         Memory trust relation: stored data is not a trusted instruction. Persisting data \
         records it and confers nothing; memory being available to a recall is not \
         authorization for it to influence a protected decision.\n\n\
         Scope: this run exercised a finite local corpus of synthetic memory under the recorded \
         conditions. Memory was described and never persisted, no Redis, PostgreSQL, vector \
         database, SaaS memory service, remote MCP server or HTTP provider was contacted, no \
         customer memory was read or written, and lifecycle was evaluated at the logical time \
         the scenario declared rather than a wall clock. Retrieval, embedding similarity, \
         vector-store authorization and document-level isolation were not evaluated. It does \
         not establish that memory or context handling holds in general, and no result here \
         should be read as a claim of universal memory security.\n",
        scenario = result.scenario_id,
        corpus = result.corpus_id.as_deref().unwrap_or("(none)"),
        property = result.property_id.as_str(),
        invariant = result.invariant.as_str(),
        invariant_surface = invariant_surface(result.invariant).as_str(),
        source = result.source_kind.as_str(),
        trust = result.source_trust.as_str(),
        store = result.store_id,
        items = result.item_digests.len(),
        principal = result.acting_principal_id,
        tenant = result.tenant_id,
        namespace = result.namespace_id,
        policy = result.policy_id.as_deref().unwrap_or("(none)"),
        mode = result.mode.as_str(),
        synthetic = if result.synthetic { "yes" } else { "no" },
        provenance = surface_state(result, ScenarioClass::Provenance),
        trust_boundary = surface_state(result, ScenarioClass::TrustBoundary),
        tenant_principal = surface_state(result, ScenarioClass::TenantPrincipal),
        lifecycle = surface_state(result, ScenarioClass::Lifecycle),
        decision_influence = surface_state(result, ScenarioClass::DecisionInfluence),
        planned = result.trials_planned,
        executed = result.trials_executed,
        recalls = result.recall_items(),
        violations = violations,
        inconclusive = inconclusive,
        stop = result.stop_reason.as_str(),
        verdict = result.verdict.as_str(),
        claim = result.bounded_claim(),
    )
}

pub fn run_memory_security(args: MemorySecurityArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(error) if error.is_refusal() => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error @ (MemorySecurityError::Invalid(_) | MemorySecurityError::Schema(_))) => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error) => {
            eprintln!("{error}");
            SCANNER_ERROR
        }
    }
}

fn run_inner(args: MemorySecurityArgs) -> Result<i32, MemorySecurityError> {
    let scenario = load_scenario(&args.scenario)?;

    // The corpus is loaded whenever the scenario names a vector, in every mode.
    // A substituted vector must be refused even when the run itself would have
    // replayed a trace.
    let entry: Option<MemoryCorpusEntry> = match scenario.vector.as_ref() {
        Some(vector) => {
            let corpus = load_corpus_for(&args)?;
            corpus.get(&vector.corpus_id).cloned()
        }
        None => None,
    };

    // Refuse a substituted store, item, policy or context before anything is
    // observed.
    let binding = bind(&scenario)?;

    let plan = dare_memory_security::trials::TrialPlan::from_scenario(&scenario)?
        .with_trial_override(args.trials)?;
    let adapter = build_adapter(&args, &scenario, plan.trials)?;
    // A trace supplies a fixed number of trials. Asking for more would end the
    // run in a harness error that says nothing about the boundary under test,
    // so the plan is reduced to what the source can actually supply. Reducing
    // is always allowed; nothing here can raise the count.
    let plan = match available_trials(adapter.as_ref()) {
        Some(available) => plan.clamped_to_available(available),
        None => plan,
    };
    let result = run_scenario(&scenario, entry.as_ref(), adapter.as_ref(), plan)?;

    let evidence = build_evidence(
        &scenario,
        entry.as_ref(),
        &binding,
        &result,
        OffsetDateTime::now_utc(),
    )?;

    validate_output_dir(&args.output_dir).map_err(MemorySecurityError::invalid)?;
    fs::create_dir_all(&args.output_dir)?;

    write_json(
        &args.output_dir.join("memory-security-result.json"),
        &result,
    )?;
    write_json(
        &args.output_dir.join("memory-security-trials.json"),
        &result.trials,
    )?;
    write_json(
        &args.output_dir.join("memory-security-evidence.json"),
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

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), MemorySecurityError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    assert_bytes_are_secret_safe(&bytes)?;
    fs::write(path, bytes)?;
    Ok(())
}

/// Refuse to write an artifact that carries a canary or credential.
fn assert_bytes_are_secret_safe(bytes: &[u8]) -> Result<(), MemorySecurityError> {
    let text = String::from_utf8_lossy(bytes);
    for marker in [
        "DARE-SYNTHETIC-CANARY-",
        "sk-live-",
        "-----BEGIN",
        "ghp_",
        "xoxb-",
        "eyJhbGci",
    ] {
        if text.contains(marker) {
            return Err(MemorySecurityError::refusal(
                "refusing to write an artifact containing sensitive content",
            ));
        }
    }
    // Anchored on shape, so an honest sentence about bearer credentials stays
    // writable while a real one is refused.
    if dare_memory_security::schema::contains_bearer_credential(&text.to_ascii_lowercase()) {
        return Err(MemorySecurityError::refusal(
            "refusing to write an artifact containing sensitive content",
        ));
    }
    Ok(())
}

/// Refuse to write a summary that overstates what was validated.
fn assert_summary_is_bounded(summary: &str) -> Result<(), MemorySecurityError> {
    let lowered = summary.to_lowercase();
    for forbidden in [
        "memory secure",
        "memory is secure",
        "poisoning impossible",
        "no memory poisoning",
        "fully protected",
        "immune",
        "guaranteed secure",
        "cannot be poisoned",
        "cannot be tampered",
        "asi06 compliant",
    ] {
        if lowered.contains(forbidden) {
            return Err(MemorySecurityError::refusal(format!(
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
    struct Harness {
        #[command(flatten)]
        args: MemorySecurityArgs,
    }

    fn parse(argv: &[&str]) -> Result<Harness, clap::Error> {
        Harness::try_parse_from(std::iter::once("harness").chain(argv.iter().copied()))
    }

    #[test]
    fn the_prohibited_store_and_credential_flags_do_not_exist() {
        // Every flag the approval forbids. A flag that parsed would imply a
        // code path able to use it, which is the thing that must not exist.
        for flag in [
            "--url",
            "--redis",
            "--postgres",
            "--vector-db",
            "--pinecone",
            "--qdrant",
            "--weaviate",
            "--provider",
            "--token",
            "--api-key",
            "--remote",
            "--command",
            "--endpoint",
            "--connection-string",
        ] {
            let result = parse(&[
                "--scenario",
                "MEMORY-LAB-001",
                "--output-dir",
                "out",
                flag,
                "value",
            ]);
            assert!(result.is_err(), "`{flag}` was accepted");
        }
    }

    #[test]
    fn the_mode_enum_admits_only_the_three_local_modes() {
        for mode in ["replay", "simulated", "local-synthetic"] {
            parse(&[
                "--scenario",
                "MEMORY-LAB-001",
                "--output-dir",
                "out",
                "--mode",
                mode,
            ])
            .unwrap_or_else(|err| panic!("{mode} should parse: {err}"));
        }

        for mode in ["live", "remote", "production", "http"] {
            assert!(
                parse(&[
                    "--scenario",
                    "MEMORY-LAB-001",
                    "--output-dir",
                    "out",
                    "--mode",
                    mode,
                ])
                .is_err(),
                "`{mode}` was accepted"
            );
        }
    }

    #[test]
    fn the_trial_count_cannot_exceed_the_hard_maximum() {
        assert!(parse(&[
            "--scenario",
            "MEMORY-LAB-001",
            "--output-dir",
            "out",
            "--trials",
            "10",
        ])
        .is_ok());

        for over in ["11", "99", "0"] {
            assert!(
                parse(&[
                    "--scenario",
                    "MEMORY-LAB-001",
                    "--output-dir",
                    "out",
                    "--trials",
                    over,
                ])
                .is_err(),
                "--trials {over} was accepted"
            );
        }
    }

    #[test]
    fn the_help_text_names_the_stores_this_command_never_reaches() {
        let help = Harness::command().render_long_help().to_string();
        for absent in ["Redis", "PostgreSQL", "Qdrant", "customer memory"] {
            assert!(help.contains(absent), "the help omits {absent}");
        }
        assert!(help.contains("never a claim that memory is secure"));
    }

    #[test]
    fn a_scenario_id_cannot_become_a_path_expression() {
        for hostile in [
            "../../etc/passwd",
            "..",
            "MEMORY-LAB-001/../../secret",
            "memory-lab-001",
        ] {
            // A path-shaped spec is read as a path and simply fails to open; a
            // lowercase or traversal id is refused outright. Either way nothing
            // outside the fixtures directory is reached by id.
            let loaded = load_scenario(hostile);
            assert!(loaded.is_err(), "`{hostile}` resolved");
        }
    }

    #[test]
    fn an_unbounded_summary_is_refused_before_it_is_written() {
        assert!(assert_summary_is_bounded("the agent's memory is secure").is_err());
        assert!(assert_summary_is_bounded("poisoning impossible").is_err());
        assert!(assert_summary_is_bounded(
            "No memory-security invariant violation was observed for the tested vectors under \
             the recorded conditions."
        )
        .is_ok());
    }

    #[test]
    fn an_artifact_carrying_a_canary_or_credential_is_refused() {
        for hostile in [
            "recalled DARE-SYNTHETIC-CANARY-MEM01 into the summary",
            "the write carried sk-live-000000000000000000000000",
            "-----BEGIN PRIVATE KEY-----",
            "Authorization: Bearer abcdefghijklmnopqrstuvwx",
        ] {
            assert!(
                assert_bytes_are_secret_safe(hostile.as_bytes()).is_err(),
                "`{hostile}` was allowed into an artifact"
            );
        }

        // An honest sentence about the boundary stays writable.
        assert!(assert_bytes_are_secret_safe(
            b"memory holding a bearer token must not become policy-authoritative"
        )
        .is_ok());
    }

    /// Load the built-in lab by absolute path.
    ///
    /// `scenarios_root` is workspace-relative because that is the working
    /// directory the command runs in; a unit test runs from its own crate
    /// directory, so it resolves the same file itself rather than changing the
    /// command's behavior to suit the test.
    fn built_in_lab(lab: &str) -> MemorySecurityScenario {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../dare-memory-security/tests/fixtures/scenarios")
            .join(format!("{}.json", lab.to_ascii_lowercase()));
        load_scenario(&path.to_string_lossy()).expect("the built-in lab loads")
    }

    #[test]
    fn a_summary_reports_every_surface_and_marks_the_untested_ones() {
        // The failure mode: four surfaces nobody exercised rendering as
        // absent, which reads as nothing to report rather than nothing tried.
        let scenario = built_in_lab("MEMORY-LAB-001");
        let plan = dare_memory_security::trials::TrialPlan::from_scenario(&scenario).expect("plan");
        let result = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan).expect("runs");
        let summary = render_summary(&result);

        for surface in [
            "PROVENANCE",
            "TRUST_BOUNDARY",
            "TENANT_PRINCIPAL",
            "LIFECYCLE",
            "DECISION_INFLUENCE",
        ] {
            assert!(summary.contains(surface), "{surface} is missing");
        }
        assert!(summary.contains("NOT TESTED"));
        assert!(summary.contains("| Memory items written | 0 |"));
        assert!(summary.contains("| External egress bytes | 0 |"));
        assert_summary_is_bounded(&summary).expect("the rendered summary is bounded");
    }

    #[test]
    fn the_summary_states_what_cycle_016_did_not_examine() {
        let scenario = built_in_lab("MEMORY-LAB-001");
        let plan = dare_memory_security::trials::TrialPlan::from_scenario(&scenario).expect("plan");
        let result = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan).expect("runs");
        let summary = render_summary(&result);

        // A reader holding this one file has no other way to learn that
        // retrieval was never looked at.
        assert!(summary.contains("Retrieval, embedding similarity"));
        assert!(summary.contains("stored data is not a trusted instruction"));
        assert!(summary.contains("logical time"));
    }
}
