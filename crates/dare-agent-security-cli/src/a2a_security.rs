//! `dare-agent-security validate a2a` (Cycle 020).
//!
//! Bounded, local, offline validation of A2A / inter-agent communication
//! evidence.
//!
//! # The flag surface is the security boundary
//!
//! Every flag here names a local path, a mode, a limit or an output location.
//! There is deliberately no `--endpoint`, `--url`, `--token`, `--api-key`,
//! `--client-secret`, `--username`, `--password`, `--private-key`,
//! `--certificate`, `--login`, `--jwks-url`, `--webhook-test`, `--command`,
//! `--shell`, `--download` or `--fetch`.
//!
//! That is not a convention: `the_help_offers_no_flag_that_could_reach_a_peer`
//! renders the actual help text and fails if one appears. A flag is the first
//! thing a hurried operator reaches for, and a subcommand that accepted a token
//! would be used with a real one within a week.
//!
//! An interface URL, issuer, `jku`, token endpoint or webhook read out of a
//! local document stays inert metadata. Nothing here resolves one.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use dare_a2a_security::budget::AdmissionLedger;
use dare_a2a_security::capture::{A2aCapture, ReplayAdapter};
use dare_a2a_security::corpus::{corpus, entry_by_id, scenario_for, CorpusAdapter};
use dare_a2a_security::error::A2aSecurityError;
use dare_a2a_security::evidence_bridge::build_evidence;
use dare_a2a_security::harness::{A2aAdapter, StaticAdapter};
use dare_a2a_security::local_synthetic::LocalSyntheticAdapter;
use dare_a2a_security::model::A2aScenario;
use dare_a2a_security::policy::A2aPolicy;
use dare_a2a_security::result::{
    assert_summary_is_bounded, render_summary, run_scenario, A2aSecurityResult,
};
use dare_a2a_security::schema::{assert_no_hostile_fields, enforce_document_size};
use dare_a2a_security::simulated::SimulatedAdapter;
use dare_a2a_security::source::A2aMode;
use serde_json::Value;
use time::OffsetDateTime;

use crate::ci_output::validate_output_dir;
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum A2aModeArg {
    Static,
    Replay,
    Simulated,
    LocalSynthetic,
}

impl From<A2aModeArg> for A2aMode {
    fn from(value: A2aModeArg) -> Self {
        match value {
            A2aModeArg::Static => Self::Static,
            A2aModeArg::Replay => Self::Replay,
            A2aModeArg::Simulated => Self::Simulated,
            A2aModeArg::LocalSynthetic => Self::LocalSynthetic,
        }
    }
}

/// `dare-agent-security validate a2a` options.
#[derive(Debug, Args)]
#[command(after_help = A2A_AFTER_HELP)]
pub struct A2aArgs {
    /// Local scenario file, or an A2A-LAB corpus id.
    #[arg(long, value_name = "PATH-OR-ID")]
    pub scenario: String,
    /// How the evidence is obtained. Every mode is local and offline.
    #[arg(long, value_enum, default_value = "simulated")]
    pub mode: A2aModeArg,
    /// Directory of local Agent Cards, traces, verification records and policy.
    #[arg(long, value_name = "PATH")]
    pub evidence_dir: Option<PathBuf>,
    /// A local capture to analyse. Analysing a capture is not re-sending it.
    #[arg(long, value_name = "PATH")]
    pub capture: Option<PathBuf>,
    /// The local policy a capture is judged against.
    #[arg(long, value_name = "PATH")]
    pub policy: Option<PathBuf>,
    /// Tighten the peer ceiling for this run. Never raises the hard maximum.
    #[arg(long, value_name = "N")]
    pub max_peers: Option<u32>,
    /// Tighten the exchange ceiling for this run. Never raises the hard maximum.
    #[arg(long, value_name = "N")]
    pub max_exchanges: Option<u32>,
    /// Where the artifacts are written.
    #[arg(long, value_name = "PATH")]
    pub output_dir: PathBuf,
    /// Also print the result artifact to stdout.
    #[arg(long)]
    pub json: bool,
}

pub const A2A_AFTER_HELP: &str = "\
Exit codes (`validate a2a`):
  0  no inter-agent invariant violation was observed
  1  harness or environment error
  2  a deterministic invariant violation was observed, or evidence was inconclusive
  3  usage error or safety refusal

Modes are local and offline: static, replay, simulated, local-synthetic.
Replay analyses a capture that already exists; it never re-sends traffic.

No peer is contacted, no Agent Card is downloaded, no .well-known path or
registry is queried, no key set is resolved, no credential is obtained or
presented, no message is sent, no task is created or cancelled, and no
callback is invoked. An interface, issuer, key-set location or callback read
out of a local document stays inert metadata.

A PASS means the applicable invariants remained satisfied under the local
evidence analysed. It is not a statement that a remote agent is secure.
";

/// Flags this subcommand must never offer.
///
/// Public so the CLI-wide help tests can assert against the same list rather
/// than a second copy that could drift.
pub const FORBIDDEN_FLAGS: [&str; 16] = [
    "--endpoint",
    "--url",
    "--token",
    "--api-key",
    "--client-secret",
    "--username",
    "--password",
    "--private-key",
    "--certificate",
    "--login",
    "--jwks-url",
    "--webhook-test",
    "--command",
    "--shell",
    "--download",
    "--fetch",
];

fn load_scenario(spec: &str) -> Result<A2aScenario, A2aSecurityError> {
    if spec.ends_with(".json") || spec.contains('/') || spec.contains('\\') {
        let raw = fs::read(spec).map_err(|error| {
            A2aSecurityError::invalid(format!(
                "scenario `{spec}` could not be read ({})",
                error.kind()
            ))
        })?;
        enforce_document_size(&raw, "the scenario")?;
        let value: Value = serde_json::from_slice(&raw)?;
        assert_no_hostile_fields(&value, "the scenario")?;
        let scenario: A2aScenario = serde_json::from_value(value)?;
        scenario.validate()?;
        return Ok(scenario);
    }

    if !spec
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(A2aSecurityError::invalid(
            "a corpus id is uppercase alphanumeric with dashes".to_owned(),
        ));
    }
    let entry = entry_by_id(spec).ok_or_else(|| {
        A2aSecurityError::invalid(format!(
            "the corpus contains no entry `{spec}`; it has {} entries",
            corpus().len()
        ))
    })?;
    Ok(scenario_for(&entry))
}

fn read_local_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    label: &str,
) -> Result<T, A2aSecurityError> {
    let raw = fs::read(path).map_err(|error| {
        A2aSecurityError::invalid(format!("{label} could not be read ({})", error.kind()))
    })?;
    enforce_document_size(&raw, label)?;
    let value: Value = serde_json::from_slice(&raw)?;
    assert_no_hostile_fields(&value, label)?;
    Ok(serde_json::from_value(value)?)
}

fn build_adapter(
    args: &A2aArgs,
    scenario: &A2aScenario,
) -> Result<Box<dyn A2aAdapter>, A2aSecurityError> {
    let mode: A2aMode = args.mode.into();

    if mode != A2aMode::Static && args.evidence_dir.is_some() {
        return Err(A2aSecurityError::invalid(
            "--evidence-dir is only valid with --mode static".to_owned(),
        ));
    }
    if mode != A2aMode::Replay && (args.capture.is_some() || args.policy.is_some()) {
        return Err(A2aSecurityError::invalid(
            "--capture and --policy are only valid with --mode replay".to_owned(),
        ));
    }

    match mode {
        A2aMode::Static => {
            let root = args.evidence_dir.as_ref().ok_or_else(|| {
                A2aSecurityError::invalid("--mode static requires --evidence-dir".to_owned())
            })?;
            if scenario.evidence_files.is_empty() {
                return Err(A2aSecurityError::invalid(
                    "a static scenario must name the evidence files it reads".to_owned(),
                ));
            }
            Ok(Box::new(StaticAdapter::new(root)))
        }
        A2aMode::Replay => {
            let capture_path = args.capture.as_ref().ok_or_else(|| {
                A2aSecurityError::invalid("--mode replay requires --capture".to_owned())
            })?;
            // The capture may not supply the policy it is judged against. A
            // capture is evidence about what happened; it is not an approval,
            // and one that could carry its own policy would let a recorded run
            // declare its own approvals.
            let policy_path = args.policy.as_ref().ok_or_else(|| {
                A2aSecurityError::invalid(
                    "--mode replay requires --policy; a capture may not supply the policy it is \
                     judged against"
                        .to_owned(),
                )
            })?;
            let capture: A2aCapture = read_local_json(capture_path, "the capture")?;
            let policy: A2aPolicy = read_local_json(policy_path, "the policy")?;
            Ok(Box::new(ReplayAdapter::new(capture, policy)))
        }
        A2aMode::Simulated => {
            if scenario.reference_behavior.is_some() {
                Ok(Box::new(SimulatedAdapter::new()))
            } else {
                Ok(Box::new(CorpusAdapter))
            }
        }
        A2aMode::LocalSynthetic => {
            if scenario.reference_behavior.is_none() {
                return Err(A2aSecurityError::invalid(
                    "local-synthetic mode requires the scenario to name a reference behaviour"
                        .to_owned(),
                ));
            }
            Ok(Box::new(LocalSyntheticAdapter::for_scenario(scenario)))
        }
    }
}

fn ledger_for(args: &A2aArgs) -> Result<AdmissionLedger, A2aSecurityError> {
    match (args.max_peers, args.max_exchanges) {
        (None, None) => Ok(AdmissionLedger::new()),
        (peers, exchanges) => AdmissionLedger::with_ceilings(
            peers.unwrap_or(dare_a2a_security::limits::HARD_MAX_PEERS),
            exchanges.unwrap_or(dare_a2a_security::limits::HARD_MAX_EXCHANGES),
        ),
    }
}

pub fn run_a2a_security(args: A2aArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(error) if error.is_refusal() => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error @ (A2aSecurityError::Invalid(_) | A2aSecurityError::Schema(_))) => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error) => {
            eprintln!("{error}");
            SCANNER_ERROR
        }
    }
}

fn run_inner(args: A2aArgs) -> Result<i32, A2aSecurityError> {
    let scenario = load_scenario(&args.scenario)?;
    let adapter = build_adapter(&args, &scenario)?;

    let mut ledger = ledger_for(&args)?;
    let mut result = run_scenario(&scenario, adapter.as_ref(), &mut ledger)?;
    let evidence = build_evidence(&scenario, &result, OffsetDateTime::now_utc())?;

    validate_output_dir(&args.output_dir).map_err(A2aSecurityError::invalid)?;
    fs::create_dir_all(&args.output_dir).map_err(|error| {
        A2aSecurityError::invalid(format!("output directory ({})", error.kind()))
    })?;

    // Serialize -> admit -> write. No persisted byte may bypass the output
    // ledger. The result artifact is written last so its budget snapshot can
    // include every retained artifact, including itself.
    write_json_admitted(
        &args.output_dir.join("a2a-peers.json"),
        &result.peers,
        &mut ledger,
    )?;
    write_json_admitted(
        &args.output_dir.join("a2a-exchanges.json"),
        &result.exchanges,
        &mut ledger,
    )?;
    write_json_admitted(
        &args.output_dir.join("a2a-findings.json"),
        &result.violations,
        &mut ledger,
    )?;
    write_json_admitted(
        &args.output_dir.join("a2a-evidence.json"),
        &evidence,
        &mut ledger,
    )?;

    let summary = render_summary(&result);
    assert_summary_is_bounded(&summary)?;
    write_bytes_admitted(
        &args.output_dir.join("summary.md"),
        summary.as_bytes(),
        &mut ledger,
        "summary",
    )?;

    let result_bytes = serialize_result_with_final_budget(&mut result, &mut ledger)?;
    fs::write(args.output_dir.join("a2a-result.json"), &result_bytes)
        .map_err(|error| A2aSecurityError::invalid(format!("artifact ({})", error.kind())))?;

    if args.json {
        println!("{}", String::from_utf8_lossy(&result_bytes));
    }

    Ok(match result.verdict {
        dare_security_evidence::Verdict::Pass => SUCCESS,
        dare_security_evidence::Verdict::Fail | dare_security_evidence::Verdict::Inconclusive => {
            PARTIAL
        }
        dare_security_evidence::Verdict::Error => SCANNER_ERROR,
    })
}

fn write_json_admitted<T: serde::Serialize>(
    path: &Path,
    value: &T,
    ledger: &mut AdmissionLedger,
) -> Result<(), A2aSecurityError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    assert_bytes_are_secret_safe(&bytes)?;
    write_bytes_admitted(path, &bytes, ledger, "artifact")
}

fn write_bytes_admitted(
    path: &Path,
    bytes: &[u8],
    ledger: &mut AdmissionLedger,
    label: &str,
) -> Result<(), A2aSecurityError> {
    ledger.admit_output(bytes.len())?;
    fs::write(path, bytes)
        .map_err(|error| A2aSecurityError::invalid(format!("{label} ({})", error.kind())))?;
    Ok(())
}

/// Charge the result artifact to a fixed point.
///
/// Writing `budget.output_bytes_used` into the artifact changes the artifact's
/// length by a few digits, which changes the budget again. The loop admits each
/// increment before anything is written, so the final artifact has accounted
/// for itself — the Cycle 019 post-merge correction, which found the budget was
/// bounding everything except the largest thing the run produced.
fn serialize_result_with_final_budget(
    result: &mut A2aSecurityResult,
    ledger: &mut AdmissionLedger,
) -> Result<Vec<u8>, A2aSecurityError> {
    let mut already_admitted = 0usize;
    loop {
        result.budget = ledger.snapshot();
        let bytes = serde_json::to_vec_pretty(&*result)?;
        assert_bytes_are_secret_safe(&bytes)?;
        if bytes.len() > already_admitted {
            ledger.admit_output(bytes.len() - already_admitted)?;
            already_admitted = bytes.len();
            continue;
        }

        result.budget = ledger.snapshot();
        let final_bytes = serde_json::to_vec_pretty(&*result)?;
        assert_bytes_are_secret_safe(&final_bytes)?;
        if final_bytes.len() > already_admitted {
            continue;
        }
        return Ok(final_bytes);
    }
}

fn assert_bytes_are_secret_safe(bytes: &[u8]) -> Result<(), A2aSecurityError> {
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
            return Err(A2aSecurityError::refusal(
                "refusing to write an artifact containing sensitive content".to_owned(),
            ));
        }
    }
    if dare_a2a_security::schema::contains_bearer_credential(&text.to_ascii_lowercase()) {
        return Err(A2aSecurityError::refusal(
            "refusing to write an artifact containing sensitive content".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser as _};

    #[derive(Debug, clap::Parser)]
    struct Harness {
        #[command(flatten)]
        args: A2aArgs,
    }

    fn rendered_help() -> String {
        Harness::command().render_long_help().to_string()
    }

    fn parse(argv: &[&str]) -> Result<Harness, clap::Error> {
        Harness::try_parse_from(std::iter::once("harness").chain(argv.iter().copied()))
    }

    #[test]
    fn the_help_offers_no_flag_that_could_reach_a_peer() {
        // The flag surface is the security boundary, so it is asserted against
        // the rendered help rather than against the struct. A flag is the first
        // thing a hurried operator reaches for, and a subcommand that accepted
        // a token would be used with a real one within a week.
        let help = rendered_help();
        for flag in FORBIDDEN_FLAGS {
            assert!(
                !help.contains(flag),
                "`validate a2a` offers `{flag}`, which could reach or authenticate to a peer"
            );
            // And it must not merely be undocumented. A flag that parses means
            // a code path able to use it, which is the thing that must not
            // exist.
            assert!(
                parse(&[
                    "--scenario",
                    "A2A-LAB-001",
                    "--output-dir",
                    "out",
                    flag,
                    "value"
                ])
                .is_err(),
                "`{flag}` parses"
            );
        }
    }

    #[test]
    fn every_flag_the_help_offers_names_a_path_a_mode_a_limit_or_an_output() {
        // The inverse of the ban list, so a *new* flag outside the four allowed
        // categories fails here even though nobody thought to ban it by name.
        const ALLOWED: [&str; 11] = [
            "--scenario",
            "--mode",
            "--evidence-dir",
            "--capture",
            "--policy",
            "--max-peers",
            "--max-exchanges",
            "--output-dir",
            "--json",
            "--help",
            "--version",
        ];
        let help = rendered_help();
        for token in help.split_whitespace() {
            let flag = token.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
            if !flag.starts_with("--") {
                continue;
            }
            assert!(
                ALLOWED.contains(&flag),
                "`{flag}` is offered and is not a local path, a mode, a limit or an output"
            );
        }
    }

    #[test]
    fn the_help_states_the_offline_boundary_and_the_bounded_claim() {
        // An operator who reads only the help must still learn what a PASS
        // covers. The two sentences most likely to be dropped in an edit are
        // asserted directly.
        let help = rendered_help();
        assert!(help.contains("never re-sends traffic"));
        assert!(help.contains("stays inert metadata"));
        assert!(help.contains("not a statement that a remote agent is secure"));
    }

    #[test]
    fn an_unknown_corpus_id_is_refused_rather_than_running_empty() {
        // Staging nothing would produce a clean run for a vector nobody
        // exercised.
        let error = load_scenario("A2A-LAB-999").expect_err("refused");
        assert!(error.to_string().contains("A2A-LAB-999"));
    }

    #[test]
    fn a_corpus_id_shaped_like_a_path_is_not_treated_as_an_id() {
        assert!(load_scenario("../../etc/passwd").is_err());
    }

    #[test]
    fn replay_requires_a_policy_the_capture_did_not_supply() {
        let scenario = load_scenario("A2A-LAB-001").expect("resolves");
        let args = A2aArgs {
            scenario: "A2A-LAB-001".to_owned(),
            mode: A2aModeArg::Replay,
            evidence_dir: None,
            capture: Some(PathBuf::from("capture.json")),
            policy: None,
            max_peers: None,
            max_exchanges: None,
            output_dir: PathBuf::from("out"),
            json: false,
        };
        let error = match build_adapter(&args, &scenario) {
            Ok(_) => panic!("a replay run without a policy must be refused"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("--policy"), "{error}");
    }

    #[test]
    fn a_flag_belonging_to_another_mode_is_refused_rather_than_ignored() {
        // Silently ignoring it would let an operator believe a capture was read
        // when the run staged a fixture instead.
        let scenario = load_scenario("A2A-LAB-001").expect("resolves");
        let args = A2aArgs {
            scenario: "A2A-LAB-001".to_owned(),
            mode: A2aModeArg::Simulated,
            evidence_dir: Some(PathBuf::from("evidence")),
            capture: None,
            policy: None,
            max_peers: None,
            max_exchanges: None,
            output_dir: PathBuf::from("out"),
            json: false,
        };
        assert!(build_adapter(&args, &scenario).is_err());
    }

    #[test]
    fn a_ceiling_flag_can_only_tighten() {
        let args = A2aArgs {
            scenario: "A2A-LAB-001".to_owned(),
            mode: A2aModeArg::Simulated,
            evidence_dir: None,
            capture: None,
            policy: None,
            max_peers: Some(u32::MAX),
            max_exchanges: Some(4),
            output_dir: PathBuf::from("out"),
            json: false,
        };
        let snapshot = ledger_for(&args).expect("builds").snapshot();
        assert_eq!(
            snapshot.max_peers,
            dare_a2a_security::limits::HARD_MAX_PEERS
        );
        assert_eq!(snapshot.max_exchanges, 4);
    }

    #[test]
    fn a_run_writes_all_six_artifacts_and_charges_every_byte() {
        let dir = tempfile::TempDir::new().expect("temp");
        let args = A2aArgs {
            scenario: "A2A-LAB-032".to_owned(),
            mode: A2aModeArg::Simulated,
            evidence_dir: None,
            capture: None,
            policy: None,
            max_peers: None,
            max_exchanges: None,
            output_dir: dir.path().to_path_buf(),
            json: false,
        };
        let code = run_inner(args).expect("runs");
        assert_eq!(code, PARTIAL, "a cross-tenant claim is a violation");

        for name in [
            "a2a-result.json",
            "a2a-peers.json",
            "a2a-exchanges.json",
            "a2a-evidence.json",
            "a2a-findings.json",
            "summary.md",
        ] {
            let path = dir.path().join(name);
            assert!(path.exists(), "{name} was not written");
            assert!(fs::metadata(&path).expect("metadata").len() > 0);
        }

        // The artifact accounts for itself: the recorded output total is at
        // least the size of the file that records it.
        let raw = fs::read(dir.path().join("a2a-result.json")).expect("reads");
        let result: A2aSecurityResult = serde_json::from_slice(&raw).expect("decodes");
        assert!(
            result.budget.output_bytes_used >= raw.len(),
            "the result artifact did not charge itself: {} < {}",
            result.budget.output_bytes_used,
            raw.len()
        );
    }

    #[test]
    fn the_findings_artifact_exists_and_is_an_array_even_when_clean() {
        // Cycle 019's lesson: a CI check counting findings needs a file to
        // count, and an absent file is not a count of zero.
        let dir = tempfile::TempDir::new().expect("temp");
        let args = A2aArgs {
            scenario: "A2A-LAB-001".to_owned(),
            mode: A2aModeArg::Simulated,
            evidence_dir: None,
            capture: None,
            policy: None,
            max_peers: None,
            max_exchanges: None,
            output_dir: dir.path().to_path_buf(),
            json: false,
        };
        assert_eq!(run_inner(args).expect("runs"), SUCCESS);

        let raw = fs::read(dir.path().join("a2a-findings.json")).expect("reads");
        let findings: Value = serde_json::from_slice(&raw).expect("decodes");
        assert_eq!(findings, serde_json::json!([]));
    }

    #[test]
    fn no_artifact_is_written_that_carries_a_credential() {
        // Anchored on shape, so this engine's own prose about bearer tokens
        // stays writable while a real credential is refused.
        assert!(assert_bytes_are_secret_safe(b"nothing to see").is_ok());
        assert!(assert_bytes_are_secret_safe(b"-----BEGIN PRIVATE KEY-----").is_err());
        assert!(assert_bytes_are_secret_safe(
            b"authorization: bearer abcdefghijklmnopqrstuvwxyz012345"
        )
        .is_err());
        assert!(
            assert_bytes_are_secret_safe(b"the run presented no bearer token to any peer").is_ok()
        );
    }
}
