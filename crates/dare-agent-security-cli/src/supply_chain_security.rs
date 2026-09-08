//! `dare-agent-security validate supply-chain` (Cycle 019).
//!
//! Bounded, local, offline validation of agentic supply-chain and AI-BOM
//! evidence. Imported coordinates remain inert metadata; no registry, model
//! hub, OCI, Git, transparency-log, signing or execution path exists here.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use dare_security_evidence::Verdict;
use dare_supply_chain_security::budget::AdmissionLedger;
use dare_supply_chain_security::corpus::{corpus, entry_by_id, scenario_for, CorpusAdapter};
use dare_supply_chain_security::error::SupplyChainError;
use dare_supply_chain_security::evidence_bridge::build_evidence;
use dare_supply_chain_security::harness::{StaticAdapter, SupplyChainAdapter};
use dare_supply_chain_security::manifest::DareManifest;
use dare_supply_chain_security::model::SupplyChainScenario;
use dare_supply_chain_security::replay::{ReplayAdapter, SupplyChainCapture};
use dare_supply_chain_security::result::{run_scenario, SupplyChainSecurityResult};
use dare_supply_chain_security::schema::{assert_no_hostile_fields, enforce_document_size};
use dare_supply_chain_security::simulated::SimulatedAdapter;
use dare_supply_chain_security::source::SupplyChainMode;
use serde_json::Value;
use time::OffsetDateTime;

use crate::ci_output::validate_output_dir;
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SupplyChainModeArg {
    Static,
    Replay,
    Simulated,
    LocalSynthetic,
}

impl From<SupplyChainModeArg> for SupplyChainMode {
    fn from(value: SupplyChainModeArg) -> Self {
        match value {
            SupplyChainModeArg::Static => Self::Static,
            SupplyChainModeArg::Replay => Self::Replay,
            SupplyChainModeArg::Simulated => Self::Simulated,
            SupplyChainModeArg::LocalSynthetic => Self::LocalSynthetic,
        }
    }
}

#[derive(Debug, Args)]
#[command(after_help = SUPPLY_CHAIN_AFTER_HELP)]
pub struct SupplyChainArgs {
    #[arg(long, value_name = "PATH-OR-ID")]
    pub scenario: String,
    #[arg(long, value_enum, default_value = "simulated")]
    pub mode: SupplyChainModeArg,
    #[arg(long, value_name = "PATH")]
    pub evidence_dir: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub capture: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub manifest: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    pub output_dir: PathBuf,
    #[arg(long)]
    pub json: bool,
}

pub const SUPPLY_CHAIN_AFTER_HELP: &str = "\
Exit codes (`validate supply-chain`):
  0  no supply-chain invariant violation was observed
  1  harness or environment error
  2  a deterministic invariant violation was observed, or evidence was inconclusive
  3  usage error or safety refusal

Modes are local and offline: static, replay, simulated, local-synthetic.
No registry, package, model-hub, container-registry, Git, transparency-log,
signing, key, token, fetch, download, resolve, extract or remote flag exists.
A component URL is inert metadata and not authorization to fetch it.
A PASS is scoped to the invariants decided from the documents actually read and
is never a claim that the supply chain is secure.
";

fn load_scenario(spec: &str) -> Result<SupplyChainScenario, SupplyChainError> {
    if spec.ends_with(".json") || spec.contains('/') || spec.contains('\\') {
        let raw = fs::read(spec).map_err(|error| {
            SupplyChainError::invalid(format!(
                "scenario `{spec}` could not be read ({})",
                error.kind()
            ))
        })?;
        enforce_document_size(&raw, "the scenario")?;
        let value: Value = serde_json::from_slice(&raw)?;
        assert_no_hostile_fields(&value, "the scenario")?;
        let scenario: SupplyChainScenario = serde_json::from_value(value)?;
        scenario.validate()?;
        return Ok(scenario);
    }

    if !spec
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(SupplyChainError::invalid(
            "a corpus id is uppercase alphanumeric with dashes".to_owned(),
        ));
    }
    let entry = entry_by_id(spec).ok_or_else(|| {
        SupplyChainError::invalid(format!(
            "the corpus contains no entry `{spec}`; it has {} entries",
            corpus().len()
        ))
    })?;
    Ok(scenario_for(&entry))
}

fn read_local_json<T: serde::de::DeserializeOwned>(
    path: &Path,
    label: &str,
) -> Result<T, SupplyChainError> {
    let raw = fs::read(path).map_err(|error| {
        SupplyChainError::invalid(format!("{label} could not be read ({})", error.kind()))
    })?;
    enforce_document_size(&raw, label)?;
    let value: Value = serde_json::from_slice(&raw)?;
    assert_no_hostile_fields(&value, label)?;
    Ok(serde_json::from_value(value)?)
}

fn build_adapter(
    args: &SupplyChainArgs,
    scenario: &SupplyChainScenario,
) -> Result<Box<dyn SupplyChainAdapter>, SupplyChainError> {
    let mode: SupplyChainMode = args.mode.into();

    if mode != SupplyChainMode::Static && args.evidence_dir.is_some() {
        return Err(SupplyChainError::invalid(
            "--evidence-dir is only valid with --mode static".to_owned(),
        ));
    }
    if mode != SupplyChainMode::Replay && (args.capture.is_some() || args.manifest.is_some()) {
        return Err(SupplyChainError::invalid(
            "--capture and --manifest are only valid with --mode replay".to_owned(),
        ));
    }

    match mode {
        SupplyChainMode::Static => {
            let root = args.evidence_dir.as_ref().ok_or_else(|| {
                SupplyChainError::invalid("--mode static requires --evidence-dir".to_owned())
            })?;
            if scenario.evidence_files.is_empty() {
                return Err(SupplyChainError::invalid(
                    "a static scenario must name the evidence files it reads".to_owned(),
                ));
            }
            Ok(Box::new(StaticAdapter::new(root)))
        }
        SupplyChainMode::Replay => {
            let capture_path = args.capture.as_ref().ok_or_else(|| {
                SupplyChainError::invalid("--mode replay requires --capture".to_owned())
            })?;
            let manifest_path = args.manifest.as_ref().ok_or_else(|| {
                SupplyChainError::invalid(
                    "--mode replay requires --manifest; a capture may not supply the policy it is judged against".to_owned(),
                )
            })?;
            let capture: SupplyChainCapture = read_local_json(capture_path, "the capture")?;
            let manifest: DareManifest = read_local_json(manifest_path, "the manifest")?;
            Ok(Box::new(ReplayAdapter::new(capture, manifest)))
        }
        SupplyChainMode::Simulated => {
            if scenario.reference_behavior.is_some() {
                Ok(Box::new(SimulatedAdapter::new()))
            } else {
                Ok(Box::new(CorpusAdapter))
            }
        }
        SupplyChainMode::LocalSynthetic => {
            if scenario.reference_behavior.is_none() {
                return Err(SupplyChainError::invalid(
                    "local-synthetic mode requires the scenario to name a reference behaviour"
                        .to_owned(),
                ));
            }
            Ok(Box::new(
                dare_supply_chain_security::local_synthetic::LocalSyntheticAdapter::for_scenario(
                    scenario,
                ),
            ))
        }
    }
}

fn render_summary(result: &SupplyChainSecurityResult) -> String {
    let decided = result.decided().len();
    let undecided = result.outcomes.len() - decided;
    let mut rows = String::new();
    for outcome in &result.outcomes {
        rows.push_str(&format!(
            "| {} | {} | {} |\n",
            outcome.invariant.as_str(),
            outcome.verdict.as_str(),
            if outcome.coverage_satisfied {
                "decided"
            } else {
                "no deciding evidence"
            }
        ));
    }

    format!(
        "# DARE Agentic Supply Chain and AI-BOM Validation\n\n\
         | Field | Value |\n|---|---|\n\
         | Scenario | {scenario} |\n| Mode | {mode} |\n| Synthetic evidence | {synthetic} |\n\n\
         ## Invariants\n\n| Invariant | Verdict | Evidence |\n|---|---|---|\n{rows}\n\
         ## Counts\n\n| Measure | Value |\n|---|---|\n\
         | Documents read | {documents} |\n| Components evaluated | {components} |\n\
         | Relationships evaluated | {relationships} |\n| Invariants decided | {decided} |\n\
         | Invariants without deciding evidence | {undecided} |\n| Violations retained | {violations} |\n\
         | State changes | 0 |\n| External egress bytes | 0 |\n| Verdict | {verdict} |\n\n\
         {reason}\n\n\
         Scope: this run read local evidence under the recorded conditions. It does not establish that the supply chain is secure and no result here should be read as a claim of universal security.\n",
        scenario = result.scenario_id,
        mode = result.mode.as_str(),
        synthetic = if result.synthetic { "yes" } else { "no" },
        rows = rows,
        documents = result.documents.len(),
        components = result.components_evaluated,
        relationships = result.relationships_evaluated,
        decided = decided,
        undecided = undecided,
        violations = result.violations.len(),
        verdict = result.verdict.as_str(),
        reason = result.reason,
    )
}

pub fn run_supply_chain_security(args: SupplyChainArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(error) if error.is_refusal() => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error @ (SupplyChainError::Invalid(_) | SupplyChainError::Schema(_))) => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error) => {
            eprintln!("{error}");
            SCANNER_ERROR
        }
    }
}

fn run_inner(args: SupplyChainArgs) -> Result<i32, SupplyChainError> {
    let scenario = load_scenario(&args.scenario)?;
    let adapter = build_adapter(&args, &scenario)?;

    let mut ledger = AdmissionLedger::new();
    let mut result = run_scenario(&scenario, adapter.as_ref(), &mut ledger)?;
    let evidence = build_evidence(&scenario, &result, OffsetDateTime::now_utc())?;

    validate_output_dir(&args.output_dir).map_err(SupplyChainError::invalid)?;
    fs::create_dir_all(&args.output_dir).map_err(|error| {
        SupplyChainError::invalid(format!("output directory ({})", error.kind()))
    })?;

    // Serialize -> admit -> write. No persisted byte may bypass the output
    // ledger. The result artifact is written last so its budget snapshot can
    // include every retained artifact, including itself.
    write_json_admitted(
        &args
            .output_dir
            .join("supply-chain-security-invariants.json"),
        &result.outcomes,
        &mut ledger,
    )?;
    write_json_admitted(
        &args.output_dir.join("supply-chain-security-evidence.json"),
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
    fs::write(
        args.output_dir.join("supply-chain-security-result.json"),
        &result_bytes,
    )
    .map_err(|error| SupplyChainError::invalid(format!("artifact ({})", error.kind())))?;

    if args.json {
        println!("{}", String::from_utf8_lossy(&result_bytes));
    }

    Ok(match result.verdict {
        Verdict::Pass => SUCCESS,
        Verdict::Fail | Verdict::Inconclusive => PARTIAL,
        Verdict::Error => SCANNER_ERROR,
    })
}

fn write_json_admitted<T: serde::Serialize>(
    path: &Path,
    value: &T,
    ledger: &mut AdmissionLedger,
) -> Result<(), SupplyChainError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    assert_bytes_are_secret_safe(&bytes)?;
    write_bytes_admitted(path, &bytes, ledger, "artifact")
}

fn write_bytes_admitted(
    path: &Path,
    bytes: &[u8],
    ledger: &mut AdmissionLedger,
    label: &str,
) -> Result<(), SupplyChainError> {
    ledger.admit_output(bytes.len())?;
    fs::write(path, bytes)
        .map_err(|error| SupplyChainError::invalid(format!("{label} ({})", error.kind())))?;
    Ok(())
}

/// Charge the result artifact to a fixed point: changing `budget.output_bytes_used`
/// can change the serialized result length by a few digits. Only after all such
/// growth has itself been admitted is the final byte string returned for write.
fn serialize_result_with_final_budget(
    result: &mut SupplyChainSecurityResult,
    ledger: &mut AdmissionLedger,
) -> Result<Vec<u8>, SupplyChainError> {
    let mut result_bytes_already_admitted = 0usize;
    loop {
        result.budget = ledger.snapshot();
        let bytes = serde_json::to_vec_pretty(&*result)?;
        assert_bytes_are_secret_safe(&bytes)?;
        if bytes.len() > result_bytes_already_admitted {
            ledger.admit_output(bytes.len() - result_bytes_already_admitted)?;
            result_bytes_already_admitted = bytes.len();
            continue;
        }

        // Refresh after the final admission. If digit growth changes the size,
        // the next iteration charges the delta before anything is written.
        result.budget = ledger.snapshot();
        let final_bytes = serde_json::to_vec_pretty(&*result)?;
        assert_bytes_are_secret_safe(&final_bytes)?;
        if final_bytes.len() > result_bytes_already_admitted {
            continue;
        }
        return Ok(final_bytes);
    }
}

fn assert_bytes_are_secret_safe(bytes: &[u8]) -> Result<(), SupplyChainError> {
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
            return Err(SupplyChainError::refusal(
                "refusing to write an artifact containing sensitive content".to_owned(),
            ));
        }
    }
    if dare_supply_chain_security::schema::contains_bearer_credential(&text.to_ascii_lowercase()) {
        return Err(SupplyChainError::refusal(
            "refusing to write an artifact containing sensitive content".to_owned(),
        ));
    }
    Ok(())
}

fn assert_summary_is_bounded(summary: &str) -> Result<(), SupplyChainError> {
    let lowered = summary.to_lowercase();
    for forbidden in [
        "fully verified",
        "fully trusted",
        "no substitution possible",
        "substitution impossible",
        "tamper-proof",
        "provably authentic",
        "all components verified",
    ] {
        if lowered.contains(forbidden) {
            return Err(SupplyChainError::refusal(format!(
                "refusing to write a summary that claims more than was validated: `{forbidden}`"
            )));
        }
    }
    if lowered.contains("supply chain is secure")
        && !lowered.contains("does not establish that the supply chain is secure")
    {
        return Err(SupplyChainError::refusal(
            "refusing to write a summary that claims more than was validated: `supply chain is secure`".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_bytes_are_admitted_before_write_and_recorded() {
        let dir = tempfile::TempDir::new().expect("temp");
        let mut ledger = AdmissionLedger::new();
        write_bytes_admitted(
            &dir.path().join("x.json"),
            b"12345",
            &mut ledger,
            "artifact",
        )
        .expect("writes");
        assert_eq!(ledger.snapshot().output_bytes_used, 5);
    }

    #[test]
    fn result_serialization_records_its_own_output_bytes() {
        let scenario = load_scenario("SUPPLY-LAB-001").expect("scenario");
        let mut ledger = AdmissionLedger::new();
        let mut result = run_scenario(&scenario, &CorpusAdapter, &mut ledger).expect("runs");
        let bytes =
            serialize_result_with_final_budget(&mut result, &mut ledger).expect("serializes");
        assert!(result.budget.output_bytes_used >= bytes.len());
        assert!(result.budget.output_bytes_used > 0);
    }

    #[test]
    fn unknown_corpus_id_is_refused() {
        assert!(load_scenario("SUPPLY-LAB-999").is_err());
    }

    #[test]
    fn replay_requires_a_manifest() {
        let scenario = load_scenario("SUPPLY-LAB-004").expect("resolves");
        let args = SupplyChainArgs {
            scenario: "SUPPLY-LAB-004".to_owned(),
            mode: SupplyChainModeArg::Replay,
            evidence_dir: None,
            capture: Some(PathBuf::from("capture.json")),
            manifest: None,
            output_dir: PathBuf::from("out"),
            json: false,
        };
        assert!(build_adapter(&args, &scenario).is_err());
    }
}
