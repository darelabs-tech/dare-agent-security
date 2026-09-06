//! `dare-agent-security validate rag-security` (Cycle 017).
//!
//! Bounded, local, offline validation of one retrieval authorization, tenant
//! and document isolation, provenance, result-set integrity, content-trust or
//! protected-nondisclosure scenario.
//!
//! The flag surface is deliberately narrow. There is no `--url`, `--endpoint`,
//! `--pinecone`, `--weaviate`, `--qdrant`, `--redis`, `--postgres`,
//! `--opensearch`, `--elasticsearch`, `--api-key`, `--token`,
//! `--connection-string`, `--remote` or `--command` option, because Cycle 017
//! has no index, provider or execution path for such a flag to reach. No
//! environment variable can supply a connection string either: this command
//! reads none.
//!
//! Modes are the three approved local ones. Documents are described from
//! fixtures and never indexed, embedded or persisted; no embedding is computed
//! or compared anywhere in the run, and no score, ranking or similarity decides
//! any verdict.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use dare_rag_security::canonical::bind;
use dare_rag_security::corpus::{builtin_corpus_root, load_corpus, RagCorpus};
use dare_rag_security::evidence_bridge::build_evidence;
use dare_rag_security::harness::{HarnessAdapter, HarnessMode};
use dare_rag_security::local_synthetic::LocalSyntheticAdapter;
use dare_rag_security::model::{RagCorpusEntry, RagInvariantType, RagSecurityScenario};
use dare_rag_security::replay::ReplayAdapter;
use dare_rag_security::result::{run_scenario, RagSecurityResult};
use dare_rag_security::schema::{enforce_document_size, validate_scenario_document};
use dare_rag_security::simulated::SimulatedAdapter;
use dare_rag_security::source::ScenarioClass;
use dare_rag_security::{RagSecurityError, Verdict};
use serde_json::Value;
use time::OffsetDateTime;

use crate::ci_output::validate_output_dir;
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

/// Approved local modes. There is no remote, provider or live-index variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RagSecurityModeArg {
    /// Evaluate a sanitized local trace without contacting any index.
    Replay,
    /// Deterministic scenario-derived observations.
    Simulated,
    /// Controlled local synthetic execution through the Cycle 009 substrate.
    LocalSynthetic,
}

impl From<RagSecurityModeArg> for HarnessMode {
    fn from(value: RagSecurityModeArg) -> Self {
        match value {
            RagSecurityModeArg::Replay => Self::Replay,
            RagSecurityModeArg::Simulated => Self::Simulated,
            RagSecurityModeArg::LocalSynthetic => Self::LocalSynthetic,
        }
    }
}

/// `validate rag-security` options.
#[derive(Debug, Args)]
#[command(after_help = RAG_SECURITY_AFTER_HELP)]
pub struct RagSecurityArgs {
    /// Scenario file path, or a built-in scenario id such as `RAG-LAB-001`.
    #[arg(long, value_name = "PATH-OR-ID")]
    pub scenario: String,

    /// Execution mode. All modes are local and offline.
    #[arg(long, value_enum, default_value = "simulated")]
    pub mode: RagSecurityModeArg,

    /// Sanitized local retrieval trace. Replay mode only.
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

pub const RAG_SECURITY_AFTER_HELP: &str = "\
Exit codes (`validate rag-security`):
  0  no RAG/retrieval-security invariant violation was observed for the tested vectors
  1  harness or environment error
  2  a deterministic invariant violation was observed, or evidence was inconclusive
  3  usage error or safety refusal

Modes are local and offline: replay, simulated, local-synthetic.
This capability has no vector database, search provider, index, endpoint or
credential flag, and it reads no connection string from the environment.
Documents are described from local synthetic fixtures and are never indexed or
persisted: no Pinecone, Weaviate, Qdrant, Redis, PostgreSQL, OpenSearch,
Elasticsearch, SaaS retrieval API, production retriever, customer corpus or
remote MCP server is involved, and no state change or external egress occurs.
No embedding is computed or compared, and no score, ranking, similarity or
reranker decides any verdict: relevance is not authorization.
Whether retrieved content acted as an instruction remains Cycle 013's judgement,
and persisted memory remains Cycle 016's; retrieved content is not memory.
A PASS is scoped to the tested vectors under the recorded conditions, and is
never a claim that RAG is secure or that leakage is impossible.
";

fn scenarios_root() -> PathBuf {
    PathBuf::from("crates/dare-rag-security/tests/fixtures/scenarios")
}

/// Resolve `--scenario` as a built-in id or a file path.
fn load_scenario(spec: &str) -> Result<RagSecurityScenario, RagSecurityError> {
    let path = if spec.ends_with(".json") || spec.contains('/') || spec.contains('\\') {
        PathBuf::from(spec)
    } else {
        // Built-in id. The pattern keeps this from becoming a path expression.
        if !spec
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(RagSecurityError::invalid(
                "scenario id must be uppercase alphanumeric with dashes",
            ));
        }
        scenarios_root().join(format!("{}.json", spec.to_ascii_lowercase()))
    };

    let raw = fs::read(&path).map_err(|err| {
        RagSecurityError::invalid(format!("scenario unavailable ({}): {err}", path.display()))
    })?;
    enforce_document_size(&raw, "scenario")?;
    let value: Value = serde_json::from_slice(&raw)
        .map_err(|err| RagSecurityError::schema(format!("scenario is not valid JSON: {err}")))?;
    validate_scenario_document(&value)?;
    let scenario: RagSecurityScenario = serde_json::from_value(value)?;
    scenario.validate()?;
    Ok(scenario)
}

fn load_corpus_for(args: &RagSecurityArgs) -> Result<RagCorpus, RagSecurityError> {
    let root = args.corpus.clone().unwrap_or_else(builtin_corpus_root);
    load_corpus(&root)
}

fn build_adapter(
    args: &RagSecurityArgs,
    scenario: &RagSecurityScenario,
    trials: u32,
) -> Result<Box<dyn HarnessAdapter>, RagSecurityError> {
    let mode: HarnessMode = args.mode.into();

    if mode != HarnessMode::Replay && args.trace.is_some() {
        return Err(RagSecurityError::invalid(
            "--trace is only valid with --mode replay",
        ));
    }

    match mode {
        HarnessMode::Replay => {
            let path = args
                .trace
                .as_ref()
                .ok_or_else(|| RagSecurityError::invalid("--mode replay requires --trace"))?;
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

fn require_lab(scenario: &RagSecurityScenario) -> Result<(), RagSecurityError> {
    if scenario.lab.is_none() {
        return Err(RagSecurityError::invalid(
            "simulated and local-synthetic modes require the scenario to declare a lab \
             reference behavior",
        ));
    }
    Ok(())
}

/// State of one retrieval-security surface for this run.
///
/// "not tested" and "passed" are different answers. A scenario exercises
/// exactly one surface; the other five are reported as untested rather than
/// quietly counted as holding.
fn surface_state(result: &RagSecurityResult, surface: ScenarioClass) -> &'static str {
    if result.class == surface {
        "TESTED"
    } else {
        "NOT TESTED"
    }
}

/// Which surface the evaluated invariant belongs to.
fn invariant_surface(invariant: RagInvariantType) -> ScenarioClass {
    invariant.surface()
}

/// Render the operator summary with bounded claim wording.
fn render_summary(result: &RagSecurityResult) -> String {
    let violations = result.violations().len();
    let inconclusive = result
        .trials
        .iter()
        .filter(|trial| trial.verdict == Verdict::Inconclusive)
        .count();

    format!(
        "# DARE RAG and Retrieval Security Validation\n\n\
         | Field | Value |\n\
         |---|---|\n\
         | Scenario | {scenario} |\n\
         | Corpus vector | {corpus} |\n\
         | Property | {property} |\n\
         | Invariant | {invariant} |\n\
         | Invariant surface | {invariant_surface} |\n\
         | Source boundary | {source} ({trust}) |\n\
         | Document store | {store} |\n\
         | Documents | {documents} |\n\
         | Chunks | {chunks} |\n\
         | Acting principal | {principal} |\n\
         | Tenant | {tenant} |\n\
         | Collections | {collections} |\n\
         | Policy | {policy} |\n\
         | Mode | {mode} |\n\
         | Synthetic observations | {synthetic} |\n\n\
         ## Surfaces\n\n\
         | Surface | State |\n\
         |---|---|\n\
         | RETRIEVAL_AUTHORIZATION | {authorization} |\n\
         | DOCUMENT_ISOLATION | {isolation} |\n\
         | PROVENANCE | {provenance} |\n\
         | RESULT_INTEGRITY | {result_integrity} |\n\
         | CONTENT_TRUST | {content_trust} |\n\
         | PROTECTED_NONDISCLOSURE | {protected} |\n\n\
         ## Counts\n\n\
         | Measure | Value |\n\
         |---|---|\n\
         | Scenarios | 1 |\n\
         | Trials planned | {planned} |\n\
         | Trials executed | {executed} |\n\
         | Queries issued | {queries} |\n\
         | Results returned | {results} |\n\
         | Violations observed | {violations} |\n\
         | Inconclusive trials | {inconclusive} |\n\
         | Documents indexed | 0 |\n\
         | Embeddings computed | 0 |\n\
         | State changes | 0 |\n\
         | External egress bytes | 0 |\n\
         | Stop reason | {stop} |\n\
         | Verdict | {verdict} |\n\n\
         {claim}\n\n\
         Retrieval trust relation: a similarity match is not a permission, retrieved content is \
         not a trusted instruction, and a high score is not a safe source. A document can be the \
         most relevant thing in the index and still sit outside the acting principal's \
         authority.\n\n\
         Scope: this run exercised a finite local corpus of synthetic documents under the \
         recorded conditions. Documents were described and never indexed, embedded or persisted; \
         no Pinecone, Weaviate, Qdrant, Redis, PostgreSQL, OpenSearch, Elasticsearch, SaaS \
         retrieval API, production retriever, remote MCP server or HTTP provider was contacted, \
         and no customer corpus was read. No embedding was computed or compared, and no score, \
         ranking, similarity or reranker decided any verdict. Whether retrieved content acted as \
         an instruction was not judged here and remains Cycle 013's; persisted memory was \
         neither produced nor read and remains Cycle 016's, because retrieved content is not \
         memory. It does not establish that retrieval holds in general, and no result here \
         should be read as a claim of universal RAG security.\n",
        scenario = result.scenario_id,
        corpus = result.corpus_id.as_deref().unwrap_or("(none)"),
        property = result.property_id.as_str(),
        invariant = result.invariant.as_str(),
        invariant_surface = invariant_surface(result.invariant).as_str(),
        source = result.source_kind.as_str(),
        trust = result.source_trust.as_str(),
        store = result.store_id,
        documents = result.document_digests.len(),
        chunks = result.chunk_digests.len(),
        principal = result.acting_principal_id,
        tenant = result.tenant_id,
        collections = result.collection_ids.join(", "),
        policy = result.policy_id,
        mode = result.mode.as_str(),
        synthetic = if result.synthetic { "yes" } else { "no" },
        authorization = surface_state(result, ScenarioClass::RetrievalAuthorization),
        isolation = surface_state(result, ScenarioClass::DocumentIsolation),
        provenance = surface_state(result, ScenarioClass::Provenance),
        result_integrity = surface_state(result, ScenarioClass::ResultIntegrity),
        content_trust = surface_state(result, ScenarioClass::ContentTrust),
        protected = surface_state(result, ScenarioClass::ProtectedNondisclosure),
        planned = result.trials_planned,
        executed = result.trials_executed,
        queries = result.queries(),
        results = result.results(),
        violations = violations,
        inconclusive = inconclusive,
        stop = result.stop_reason.as_str(),
        verdict = result.verdict.as_str(),
        claim = result.bounded_claim(),
    )
}

pub fn run_rag_security(args: RagSecurityArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(error) if error.is_refusal() => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error @ (RagSecurityError::Invalid(_) | RagSecurityError::Schema(_))) => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error) => {
            eprintln!("{error}");
            SCANNER_ERROR
        }
    }
}

fn run_inner(args: RagSecurityArgs) -> Result<i32, RagSecurityError> {
    let scenario = load_scenario(&args.scenario)?;

    // The corpus is loaded whenever the scenario names a vector, in every mode.
    // A substituted vector must be refused even when the run itself would have
    // replayed a trace.
    let entry: Option<RagCorpusEntry> = match scenario.vector.as_ref() {
        Some(vector) => {
            let corpus = load_corpus_for(&args)?;
            corpus.get(&vector.corpus_id).cloned()
        }
        None => None,
    };

    // Refuse a substituted document, chunk, policy or context before anything
    // is observed.
    let binding = bind(&scenario)?;

    let plan = dare_rag_security::trials::TrialPlan::from_scenario(&scenario)?
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

    validate_output_dir(&args.output_dir).map_err(RagSecurityError::invalid)?;
    fs::create_dir_all(&args.output_dir)?;

    write_json(&args.output_dir.join("rag-security-result.json"), &result)?;
    write_json(
        &args.output_dir.join("rag-security-trials.json"),
        &result.trials,
    )?;
    write_json(
        &args.output_dir.join("rag-security-evidence.json"),
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

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), RagSecurityError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    assert_bytes_are_secret_safe(&bytes)?;
    fs::write(path, bytes)?;
    Ok(())
}

/// Refuse to write an artifact that carries a canary or credential.
fn assert_bytes_are_secret_safe(bytes: &[u8]) -> Result<(), RagSecurityError> {
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
            return Err(RagSecurityError::refusal(
                "refusing to write an artifact containing sensitive content",
            ));
        }
    }
    // Anchored on shape, so an honest sentence about bearer credentials stays
    // writable while a real one is refused.
    if dare_rag_security::schema::contains_bearer_credential(&text.to_ascii_lowercase()) {
        return Err(RagSecurityError::refusal(
            "refusing to write an artifact containing sensitive content",
        ));
    }
    Ok(())
}

/// Refuse to write a summary that overstates what was validated.
fn assert_summary_is_bounded(summary: &str) -> Result<(), RagSecurityError> {
    let lowered = summary.to_lowercase();
    for forbidden in [
        "rag secure",
        "rag is secure",
        "vector database secure",
        "vector store secure",
        "no leakage possible",
        "leakage impossible",
        "fully protected",
        "no retrieval attack possible",
        "retrieval is secure",
        "immune",
        "guaranteed secure",
        "cannot be retrieved",
        "llm09 compliant",
    ] {
        if lowered.contains(forbidden) {
            return Err(RagSecurityError::refusal(format!(
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
        args: RagSecurityArgs,
    }

    fn parse(argv: &[&str]) -> Result<Harness, clap::Error> {
        Harness::try_parse_from(std::iter::once("harness").chain(argv.iter().copied()))
    }

    #[test]
    fn the_prohibited_store_provider_and_credential_flags_do_not_exist() {
        // Every flag the approval forbids by name, plus the store-specific ones
        // that would each imply their own client. A flag that parsed would mean
        // a code path able to use it, which is the thing that must not exist.
        for flag in [
            "--url",
            "--endpoint",
            "--pinecone",
            "--weaviate",
            "--qdrant",
            "--redis",
            "--postgres",
            "--opensearch",
            "--elasticsearch",
            "--api-key",
            "--token",
            "--connection-string",
            "--remote",
            "--command",
            "--provider",
            "--index",
            "--embedding-model",
        ] {
            let result = parse(&[
                "--scenario",
                "RAG-LAB-001",
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
                "RAG-LAB-001",
                "--output-dir",
                "out",
                "--mode",
                mode,
            ])
            .unwrap_or_else(|err| panic!("{mode} should parse: {err}"));
        }

        for mode in [
            "live",
            "remote",
            "provider",
            "vector-db",
            "http",
            "production",
        ] {
            assert!(
                parse(&[
                    "--scenario",
                    "RAG-LAB-001",
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
            "RAG-LAB-001",
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
                    "RAG-LAB-001",
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
        for absent in [
            "Pinecone",
            "Weaviate",
            "Qdrant",
            "Elasticsearch",
            "customer corpus",
        ] {
            assert!(help.contains(absent), "the help omits {absent}");
        }
        assert!(help.contains("relevance is not authorization"));
        assert!(help.contains("never a claim that RAG is secure"));
    }

    #[test]
    fn a_scenario_id_cannot_become_a_path_expression() {
        for hostile in [
            "../../etc/passwd",
            "..",
            "RAG-LAB-001/../../secret",
            "rag-lab-001",
        ] {
            // A path-shaped spec is read as a path and simply fails to open; a
            // lowercase or traversal id is refused outright. Either way nothing
            // outside the fixtures directory is reached by id.
            assert!(load_scenario(hostile).is_err(), "`{hostile}` resolved");
        }
    }

    #[test]
    fn an_unbounded_summary_is_refused_before_it_is_written() {
        for hostile in [
            "the corpus is RAG secure",
            "no leakage possible",
            "the vector database secure under all inputs",
            "no retrieval attack possible",
        ] {
            assert!(
                assert_summary_is_bounded(hostile).is_err(),
                "`{hostile}` was allowed"
            );
        }

        assert!(assert_summary_is_bounded(
            "No RAG/retrieval-security invariant violation was observed for the tested vectors \
             under the recorded conditions."
        )
        .is_ok());
    }

    #[test]
    fn an_artifact_carrying_a_canary_or_credential_is_refused() {
        for hostile in [
            "returned DARE-SYNTHETIC-CANARY-RAG01 in a result",
            "the chunk carried sk-live-000000000000000000000000",
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
            b"a retrieved document holding a bearer token must not become policy-authoritative"
        )
        .is_ok());
    }

    /// Load the built-in lab by absolute path.
    ///
    /// `scenarios_root` is workspace-relative because that is the working
    /// directory the command runs in; a unit test runs from its own crate
    /// directory, so it resolves the same file itself rather than changing the
    /// command's behavior to suit the test.
    fn built_in_lab(lab: &str) -> RagSecurityScenario {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../dare-rag-security/tests/fixtures/scenarios")
            .join(format!("{}.json", lab.to_ascii_lowercase()));
        load_scenario(&path.to_string_lossy()).expect("the built-in lab loads")
    }

    fn rendered(lab: &str) -> String {
        let scenario = built_in_lab(lab);
        let plan = dare_rag_security::trials::TrialPlan::from_scenario(&scenario).expect("plan");
        let result = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan).expect("runs");
        render_summary(&result)
    }

    #[test]
    fn a_summary_reports_every_surface_and_marks_the_untested_ones() {
        // The failure mode: five surfaces nobody exercised rendering as absent,
        // which reads as nothing to report rather than nothing tried.
        let summary = rendered("RAG-LAB-001");

        for surface in [
            "RETRIEVAL_AUTHORIZATION",
            "DOCUMENT_ISOLATION",
            "PROVENANCE",
            "RESULT_INTEGRITY",
            "CONTENT_TRUST",
            "PROTECTED_NONDISCLOSURE",
        ] {
            assert!(summary.contains(surface), "{surface} is missing");
        }
        assert!(summary.contains("NOT TESTED"));
        assert!(summary.contains("| Documents indexed | 0 |"));
        assert!(summary.contains("| Embeddings computed | 0 |"));
        assert!(summary.contains("| External egress bytes | 0 |"));
        assert_summary_is_bounded(&summary).expect("the rendered summary is bounded");
    }

    #[test]
    fn the_summary_states_what_cycle_017_did_not_examine() {
        // A reader holding this one file has no other way to learn that
        // instruction-following and persisted memory were never looked at.
        let summary = rendered("RAG-LAB-001");
        assert!(summary.contains("similarity match is not a permission"));
        assert!(summary.contains("Cycle 013"));
        assert!(summary.contains("retrieved content is not"));
        assert!(summary.contains("No embedding was computed"));
    }

    #[test]
    fn a_summary_of_a_violated_run_still_carries_no_retrieved_content() {
        // The report of a leak is the place most likely to quote the thing that
        // leaked. Lab 016 returns a protected document; the summary must name
        // the finding without reproducing what was disclosed.
        let summary = rendered("RAG-LAB-016");
        assert!(summary.contains("| Verdict | FAIL |"));
        assert_summary_is_bounded(&summary).expect("a failing summary is still bounded");
        assert!(!summary.contains("DARE-SYNTHETIC-CANARY-"));
    }
}
