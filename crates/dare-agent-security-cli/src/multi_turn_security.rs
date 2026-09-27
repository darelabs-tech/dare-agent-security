//! `dare-agent-security validate multi-turn` (Cycle 021).
//!
//! Bounded, local, offline validation of adaptive multi-turn adversarial
//! conversations.
//!
//! # The flag surface is the security boundary
//!
//! Every flag names a local path, a mode, a lower bound or an output
//! location. There is deliberately no `--model`, `--provider`, `--endpoint`,
//! `--url`, `--api-key`, `--token`, `--seed`, `--temperature`, `--generate`,
//! `--mutate`, `--plugin`, `--command` or `--shell`:
//! `the_help_offers_no_flag_that_could_reach_or_generate` renders the help and
//! fails if one appears or parses.
//!
//! # Which modes take which scenarios
//!
//! SIMULATED and LOCAL_SYNTHETIC drive the lab's deterministic reference
//! agents, so they run MULTITURN-LAB corpus ids only. A scenario read from a
//! file runs in REPLAY over a transcript you supply: there is no flag that
//! would let a real scenario be labelled with a synthetic behaviour.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use dare_multi_turn_security::budget::OutputLedger;
use dare_multi_turn_security::corpus::{adapter_for, entry_by_id, graph_set, LabCase, CORPUS};
use dare_multi_turn_security::coverage::coverage_report;
use dare_multi_turn_security::error::MultiTurnError;
use dare_multi_turn_security::evidence_bridge::{build_evidence, evidence_index};
use dare_multi_turn_security::graph::StrategyGraph;
use dare_multi_turn_security::harness::ConversationAdapter;
use dare_multi_turn_security::limits::{Bounds, MAX_CONVERSATIONS};
use dare_multi_turn_security::model::{GraphSet, HarnessMode, MultiTurnScenario};
use dare_multi_turn_security::replay::{ReplayAdapter, Transcript};
use dare_multi_turn_security::result::{json_bytes, render_artifacts, run_scenario, Artifact};
use dare_multi_turn_security::schema::DocumentKind;
use dare_multi_turn_security::source::admit_file;
use dare_security_evidence::Verdict;
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::ci_output::validate_output_dir;
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MultiTurnModeArg {
    Replay,
    Simulated,
    LocalSynthetic,
}

impl From<MultiTurnModeArg> for HarnessMode {
    fn from(value: MultiTurnModeArg) -> Self {
        match value {
            MultiTurnModeArg::Replay => Self::Replay,
            MultiTurnModeArg::Simulated => Self::Simulated,
            MultiTurnModeArg::LocalSynthetic => Self::LocalSynthetic,
        }
    }
}

/// `dare-agent-security validate multi-turn` options.
#[derive(Debug, Args)]
#[command(after_help = MULTI_TURN_AFTER_HELP)]
pub struct MultiTurnArgs {
    /// A MULTITURN-LAB corpus id (`multiturn-lab-NNN`) or a local scenario file.
    #[arg(long, value_name = "PATH-OR-ID")]
    pub scenario: String,
    /// A local strategy-graph file (repeatable, up to 4). Required with a scenario file.
    #[arg(long, value_name = "PATH")]
    pub graph: Vec<PathBuf>,
    /// A local recorded transcript. Required with `--mode replay` and a scenario file.
    #[arg(long, value_name = "PATH")]
    pub transcript: Option<PathBuf>,
    /// How responses are obtained. Every mode is local and offline.
    #[arg(long, value_enum, default_value = "simulated")]
    pub mode: MultiTurnModeArg,
    /// Lower the per-conversation turn bound (1–32). Never raises it.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=32))]
    pub max_turns: Option<u32>,
    /// Lower the per-graph path bound (1–64). Never raises it.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u64).range(1..=64))]
    pub max_paths: Option<u64>,
    /// Where the artifacts are written.
    #[arg(long, value_name = "PATH")]
    pub output_dir: PathBuf,
    /// Also print the result artifact to stdout.
    #[arg(long)]
    pub json: bool,
}

pub const MULTI_TURN_AFTER_HELP: &str = "\
Exit codes (`validate multi-turn`):
  0  the property held on every turn of the path the target selected
  1  harness error or strategy fault
  2  a cross-turn violation was observed, or the evidence was inconclusive
  3  usage error or refusal (nothing is written)

Modes are local and offline: replay, simulated, local-synthetic.
Simulated and local-synthetic run MULTITURN-LAB corpus ids; a scenario file
runs in replay over a transcript you supply.

Every turn is a pre-authored node of a strategy graph whose digest the
scenario pins. Nothing is generated, mutated or paraphrased, no model or
provider is called, and no URL found in a turn is fetched.

A PASS covers only the path the target selected through the graph. It is
not a statement that the agent is secure.
";

/// Flags this subcommand must never offer.
pub const FORBIDDEN_FLAGS: [&str; 16] = [
    "--model",
    "--provider",
    "--endpoint",
    "--url",
    "--api-key",
    "--token",
    "--seed",
    "--temperature",
    "--generate",
    "--mutate",
    "--template",
    "--plugin",
    "--command",
    "--shell",
    "--fetch",
    "--download",
];

#[derive(Debug)]
enum CliError {
    Usage(String),
    Engine(MultiTurnError),
}

impl From<MultiTurnError> for CliError {
    fn from(error: MultiTurnError) -> Self {
        Self::Engine(error)
    }
}

fn usage(message: impl Into<String>) -> CliError {
    CliError::Usage(message.into())
}

fn is_corpus_id(spec: &str) -> bool {
    spec.len() == "multiturn-lab-000".len()
        && spec.starts_with("multiturn-lab-")
        && spec["multiturn-lab-".len()..]
            .bytes()
            .all(|b| b.is_ascii_digit())
}

fn parse<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
    what: &'static str,
) -> Result<T, MultiTurnError> {
    serde_json::from_value(value)
        .map_err(|_| MultiTurnError::Schema(format!("{what} does not match its model")))
}

fn load_case(args: &MultiTurnArgs) -> Result<LabCase, CliError> {
    let mode: HarnessMode = args.mode.into();
    if is_corpus_id(&args.scenario) {
        if !args.graph.is_empty() || args.transcript.is_some() {
            return Err(usage(
                "--graph and --transcript are for scenario files, not corpus ids",
            ));
        }
        let entry = entry_by_id(&args.scenario).ok_or_else(|| {
            usage(format!(
                "the corpus has no such entry; it has {} entries",
                CORPUS.len()
            ))
        })?;
        if !entry.modes().contains(&mode) {
            return Err(usage(format!("{} is not staged for this mode", entry.id)));
        }
        return Ok(entry.case());
    }

    let path = Path::new(&args.scenario);
    if !path.is_file() {
        return Err(usage(
            "--scenario is neither a corpus id nor a readable file",
        ));
    }
    if mode != HarnessMode::Replay {
        return Err(usage(
            "a scenario file runs in --mode replay; simulated agents belong to the corpus",
        ));
    }
    if args.graph.is_empty() || args.graph.len() > MAX_CONVERSATIONS {
        return Err(usage("a scenario file needs between 1 and 4 --graph files"));
    }
    let transcript_path = args
        .transcript
        .as_ref()
        .ok_or_else(|| usage("--mode replay needs --transcript"))?;
    let scenario: MultiTurnScenario = parse(admit_file(path, DocumentKind::Scenario)?, "scenario")?;
    let graphs = args
        .graph
        .iter()
        .map(|g| {
            admit_file(g, DocumentKind::StrategyGraph).and_then(|v| parse(v, "strategy graph"))
        })
        .collect::<Result<Vec<StrategyGraph>, MultiTurnError>>()?;
    let transcript: Transcript = parse(
        admit_file(transcript_path, DocumentKind::Transcript)?,
        "transcript",
    )?;
    Ok(LabCase {
        scenario,
        graphs,
        source: dare_multi_turn_security::corpus::Source::Transcript(transcript),
    })
}

/// Apply the CLI's lower bounds on top of whatever the scenario already set.
fn lower_bounds(case: &mut LabCase, args: &MultiTurnArgs) {
    let mut bounds = case.scenario.bounds.unwrap_or_default();
    if let Some(turns) = args.max_turns {
        bounds.max_turns_per_conversation = Some(
            bounds
                .max_turns_per_conversation
                .map_or(turns, |b| b.min(turns)),
        );
    }
    if let Some(paths) = args.max_paths {
        bounds.max_paths = Some(bounds.max_paths.map_or(paths, |b| b.min(paths)));
    }
    if bounds != Bounds::default() {
        case.scenario.bounds = Some(bounds);
    }
}

fn adapter(case: &LabCase, mode: HarnessMode) -> Result<Box<dyn ConversationAdapter>, CliError> {
    match (&case.source, mode) {
        (dare_multi_turn_security::corpus::Source::Transcript(t), HarnessMode::Replay) => {
            Ok(Box::new(ReplayAdapter::new(t.clone(), &case.scenario)?))
        }
        _ => Ok(adapter_for(case, mode)?),
    }
}

fn write_all(dir: &Path, artifacts: &[Artifact]) -> Result<(), CliError> {
    validate_output_dir(dir).map_err(usage)?;
    fs::create_dir_all(dir).map_err(|e| usage(format!("output directory ({})", e.kind())))?;
    for artifact in artifacts {
        fs::write(dir.join(artifact.name), &artifact.bytes)
            .map_err(|e| CliError::Engine(MultiTurnError::Io(e.kind().to_string())))?;
    }
    Ok(())
}

fn run_inner(args: &MultiTurnArgs) -> Result<i32, CliError> {
    validate_output_dir(&args.output_dir).map_err(usage)?;
    let mut case = load_case(args)?;
    lower_bounds(&mut case, args);
    let graphs: GraphSet = graph_set(&case)?;
    let mut adapter = adapter(&case, args.mode.into())?;
    let mut ledger = OutputLedger::new(case.scenario.effective_bounds()?);
    let now = OffsetDateTime::now_utc();
    let generated_at = now
        .format(&Rfc3339)
        .map_err(|_| MultiTurnError::Serialization { kind: "timestamp" })?;
    let (result, run) = run_scenario(
        &case.scenario,
        &graphs,
        adapter.as_mut(),
        &mut ledger,
        &generated_at,
    )?;

    let records = build_evidence(&result, now)?;
    let coverage = coverage_report(&result, &evidence_index(&records, &result))?;
    let evidence = Artifact {
        name: "multi-turn-evidence.json",
        bytes: json_bytes(
            &json!({ "schema_version": "1", "records": records, "coverage": coverage }),
            "evidence artifact",
        )?,
    };
    // Every artifact is serialized and admitted before any is written, so a
    // refused budget leaves the output directory untouched.
    let artifacts = render_artifacts(&result, &run, vec![evidence], &mut ledger)?;
    write_all(&args.output_dir, &artifacts)?;
    if args.json {
        if let Some(r) = artifacts
            .iter()
            .find(|a| a.name == "multi-turn-result.json")
        {
            println!("{}", String::from_utf8_lossy(&r.bytes));
        }
    }
    Ok(match result.verdict {
        Verdict::Pass => SUCCESS,
        Verdict::Fail | Verdict::Inconclusive => PARTIAL,
        Verdict::Error => SCANNER_ERROR,
    })
}

pub fn run_multi_turn_security(args: MultiTurnArgs) -> i32 {
    match run_inner(&args) {
        Ok(code) => code,
        Err(CliError::Usage(message)) => {
            eprintln!("{message}");
            UNSUPPORTED_TARGET
        }
        Err(CliError::Engine(error)) if error.is_refusal() => {
            eprintln!("refused: {error}");
            UNSUPPORTED_TARGET
        }
        Err(CliError::Engine(error)) => {
            eprintln!("{error}");
            SCANNER_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser as _};
    use dare_multi_turn_security::corpus::Source;

    #[derive(Debug, clap::Parser)]
    struct Harness {
        #[command(flatten)]
        args: MultiTurnArgs,
    }

    fn parse(argv: &[&str]) -> Result<Harness, clap::Error> {
        Harness::try_parse_from(std::iter::once("harness").chain(argv.iter().copied()))
    }

    fn run(argv: &[&str]) -> i32 {
        run_multi_turn_security(parse(argv).expect("parses").args)
    }

    fn out() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("out").to_string_lossy().into_owned();
        (dir, path)
    }

    #[test]
    fn the_help_offers_no_flag_that_could_reach_or_generate() {
        let help = Harness::command().render_long_help().to_string();
        for flag in FORBIDDEN_FLAGS {
            assert!(
                !help.contains(flag),
                "`validate multi-turn` offers `{flag}`"
            );
            assert!(
                parse(&[
                    "--scenario",
                    "multiturn-lab-001",
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
    fn bounds_above_the_hard_maxima_do_not_parse() {
        for (flag, value) in [
            ("--max-turns", "33"),
            ("--max-turns", "0"),
            ("--max-paths", "65"),
        ] {
            assert!(
                parse(&[
                    "--scenario",
                    "multiturn-lab-001",
                    "--output-dir",
                    "out",
                    flag,
                    value
                ])
                .is_err(),
                "{flag} {value}"
            );
        }
    }

    #[test]
    fn a_control_passes_and_writes_every_artifact() {
        let (_dir, out) = out();
        assert_eq!(
            run(&[
                "--scenario",
                "multiturn-lab-001",
                "--mode",
                "simulated",
                "--output-dir",
                &out
            ]),
            SUCCESS
        );
        for name in [
            "multi-turn-result.json",
            "multi-turn-conversations.json",
            "multi-turn-evidence.json",
            "multi-turn-findings.json",
            "summary.md",
        ] {
            assert!(Path::new(&out).join(name).is_file(), "{name}");
        }
        let result: serde_json::Value = serde_json::from_slice(
            &fs::read(Path::new(&out).join("multi-turn-result.json")).expect("read"),
        )
        .expect("json");
        assert_eq!(result["verdict"], "PASS");
        assert_eq!(result["synthetic"], true);
    }

    #[test]
    fn an_attack_exits_two_in_local_synthetic_mode() {
        let (_dir, out) = out();
        assert_eq!(
            run(&[
                "--scenario",
                "multiturn-lab-002",
                "--mode",
                "local-synthetic",
                "--output-dir",
                &out
            ]),
            PARTIAL
        );
    }

    #[test]
    fn a_harness_fault_exits_one() {
        let (_dir, out) = out();
        assert_eq!(
            run(&["--scenario", "multiturn-lab-038", "--output-dir", &out]),
            SCANNER_ERROR
        );
    }

    #[test]
    fn refusals_exit_three_and_write_nothing() {
        for argv in [
            vec!["--scenario", "multiturn-lab-041"],
            vec!["--scenario", "multiturn-lab-999"],
            vec!["--scenario", "multiturn-lab-027", "--mode", "simulated"],
            vec!["--scenario", "../../etc/passwd"],
        ] {
            let (_dir, out) = out();
            let mut full = argv.clone();
            full.extend(["--output-dir", &out]);
            assert_eq!(run(&full), UNSUPPORTED_TARGET, "{argv:?}");
            assert!(!Path::new(&out).exists(), "{argv:?} wrote output");
        }
        assert_eq!(
            run(&[
                "--scenario",
                "multiturn-lab-001",
                "--output-dir",
                "../escape"
            ]),
            UNSUPPORTED_TARGET
        );
    }

    #[test]
    fn lowered_bounds_that_the_graph_exceeds_are_a_refusal() {
        let (_dir, out) = out();
        assert_eq!(
            run(&[
                "--scenario",
                "multiturn-lab-001",
                "--max-turns",
                "2",
                "--output-dir",
                &out
            ]),
            UNSUPPORTED_TARGET
        );
    }

    /// Export a replay corpus entry to files, the way a user would supply them.
    fn export(entry: &str, dir: &Path) -> (String, Vec<String>, String) {
        let case = entry_by_id(entry).expect("entry").case();
        let write = |name: &str, value: serde_json::Value| {
            let p = dir.join(name);
            fs::write(&p, serde_json::to_vec_pretty(&value).expect("json")).expect("write");
            p.to_string_lossy().into_owned()
        };
        let scenario = write(
            "scenario.json",
            serde_json::to_value(&case.scenario).expect("json"),
        );
        let graphs = case
            .graphs
            .iter()
            .enumerate()
            .map(|(i, g)| {
                write(
                    &format!("graph-{i}.json"),
                    serde_json::to_value(g).expect("json"),
                )
            })
            .collect();
        let Source::Transcript(t) = case.source else {
            panic!("a replay entry")
        };
        let transcript = write("transcript.json", serde_json::to_value(&t).expect("json"));
        (scenario, graphs, transcript)
    }

    #[test]
    fn scenario_files_replay_over_a_local_transcript() {
        let (dir, out) = out();
        let (scenario, graphs, transcript) = export("multiturn-lab-027", dir.path());
        let mut argv = vec![
            "--scenario",
            scenario.as_str(),
            "--mode",
            "replay",
            "--transcript",
            transcript.as_str(),
            "--output-dir",
            out.as_str(),
        ];
        for g in &graphs {
            argv.extend(["--graph", g.as_str()]);
        }
        assert_eq!(run(&argv), PARTIAL, "the recorded approval reuse is a FAIL");
        let result: serde_json::Value = serde_json::from_slice(
            &fs::read(Path::new(&out).join("multi-turn-result.json")).expect("read"),
        )
        .expect("json");
        assert_eq!(
            (result["verdict"].as_str(), result["synthetic"].as_bool()),
            (Some("FAIL"), Some(false))
        );
    }

    #[test]
    fn a_scenario_file_cannot_be_run_by_a_simulated_agent() {
        let (dir, out) = out();
        let (scenario, graphs, _) = export("multiturn-lab-027", dir.path());
        assert_eq!(
            run(&[
                "--scenario",
                &scenario,
                "--graph",
                &graphs[0],
                "--mode",
                "simulated",
                "--output-dir",
                &out
            ]),
            UNSUPPORTED_TARGET
        );
        assert_eq!(
            run(&[
                "--scenario",
                &scenario,
                "--graph",
                &graphs[0],
                "--mode",
                "replay",
                "--output-dir",
                &out
            ]),
            UNSUPPORTED_TARGET,
            "replay without --transcript"
        );
    }
}
