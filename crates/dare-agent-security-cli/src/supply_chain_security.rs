//! `dare-agent-security validate supply-chain` (Cycle 019).
//!
//! Bounded, local, offline validation of agentic supply-chain and AI-BOM
//! evidence: component identity, artifact integrity, source trust, provenance
//! and attestation binding, dependency-graph integrity, capability drift, model
//! lineage, dataset provenance and bill-of-materials completeness.
//!
//! The flag surface is deliberately narrow. There is no `--registry`,
//! `--registry-url`, `--fetch`, `--download`, `--resolve`, `--model-hub`,
//! `--oci`, `--git`, `--rekor`, `--fulcio`, `--transparency-log`, `--sign`,
//! `--key`, `--private-key`, `--token`, `--remote`, `--command` or `--extract`
//! option, because there is no code path such a flag could reach: the engine
//! declares no HTTP client, registry client, OCI client, Git library, model
//! runtime or archive extractor. No environment variable can supply one either
//! — this command reads none.
//!
//! This matters more here than in most commands, because the documents this
//! engine reads are *full of coordinates*. A CycloneDX component carries a
//! purl; an SPDX package carries a download location; an attestation names a
//! repository. Every one of those is a place something could be fetched from,
//! and all of them are inert metadata: a coordinate names something, and naming
//! something is not authorization to go and get it.
//!
//! Nothing here signs anything, issues an attestation, verifies a signature
//! against a key server, or executes, loads or extracts an artifact, model or
//! archive named in an imported document.

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

/// Approved local modes. There is no remote, live, registry or fetch variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SupplyChainModeArg {
    /// Read local bill-of-materials, provenance and attestation documents.
    Static,
    /// Re-evaluate a previously captured local evidence bundle.
    Replay,
    /// Deterministic corpus-derived evidence.
    Simulated,
    /// Locally generated documents read back through the real importer.
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

/// `validate supply-chain` options.
#[derive(Debug, Args)]
#[command(after_help = SUPPLY_CHAIN_AFTER_HELP)]
pub struct SupplyChainArgs {
    /// Scenario file path, or a built-in corpus id such as `SUPPLY-LAB-004`.
    #[arg(long, value_name = "PATH-OR-ID")]
    pub scenario: String,

    /// Execution mode. All modes are local and offline.
    #[arg(long, value_enum, default_value = "simulated")]
    pub mode: SupplyChainModeArg,

    /// Directory holding the local evidence documents. Static mode only.
    #[arg(long, value_name = "PATH")]
    pub evidence_dir: Option<PathBuf>,

    /// A previously captured local evidence bundle. Replay mode only.
    #[arg(long, value_name = "PATH")]
    pub capture: Option<PathBuf>,

    /// The local DARE manifest that supplies approvals. Replay mode only.
    ///
    /// Separate from the capture on purpose: a recording that supplied both the
    /// evidence and the policy it is judged against could approve itself.
    #[arg(long, value_name = "PATH")]
    pub manifest: Option<PathBuf>,

    /// Directory for the result, evidence and summary artifacts.
    #[arg(long, value_name = "PATH")]
    pub output_dir: PathBuf,

    /// Write the result JSON to stdout. Diagnostics go to stderr.
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
This capability has no registry, package, model-hub, container-registry, Git,
transparency-log, signing, key, token, fetch, download, resolve, extract or
remote flag, and it reads no credential from the environment. No package
registry, model hub, container registry, Git host, transparency log, signing
service, key server or vulnerability database is contacted; no signature or
attestation is issued; no artifact, model, archive or code from an imported
document is executed, loaded or extracted; and no state change or external
egress occurs.
A purl, download location, repository or registry coordinate inside an imported
document is inert metadata. Naming a location is not authorization to fetch it.
An inventory is not trust, a component name is not a component identity, a
version string is not an immutable artifact, a digest is not provenance, a valid
signature is not an approved signer, and a complete AI-BOM is not a secure
supply chain.
A PASS is scoped to the invariants decided from the documents actually read, and
is never a claim that the supply chain is secure.
";

/// Resolve `--scenario` as a built-in corpus id or a file path.
fn load_scenario(spec: &str) -> Result<SupplyChainScenario, SupplyChainError> {
    if spec.ends_with(".json") || spec.contains('/') || spec.contains('\\') {
        let raw = fs::read(spec).map_err(|error| {
            // The message names what the caller asked for, never the resolved
            // path: an error message is a persistence surface too.
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

    // A built-in corpus id. The pattern keeps this from becoming a path
    // expression.
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

    // A flag that belongs to another mode is a usage error rather than
    // something to ignore: silently dropping `--capture` under `--mode static`
    // would run a different evidence set than the operator asked for.
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
                    "--mode replay requires --manifest; a capture may not supply the policy it \
                     is judged against"
                        .to_owned(),
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
                // A built-in corpus scenario names no behaviour; it names an
                // entry, and the corpus knows how to stage it.
                Ok(Box::new(CorpusAdapter))
            }
        }
        SupplyChainMode::LocalSynthetic => {
            let behavior = scenario.reference_behavior.ok_or_else(|| {
                SupplyChainError::invalid(
                    "local-synthetic mode requires the scenario to name a reference behaviour"
                        .to_owned(),
                )
            })?;
            let _ = behavior;
            Ok(Box::new(
                dare_supply_chain_security::local_synthetic::LocalSyntheticAdapter::for_scenario(
                    scenario,
                ),
            ))
        }
    }
}

/// Render the operator summary with bounded claim wording.
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
         | Field | Value |\n\
         |---|---|\n\
         | Scenario | {scenario} |\n\
         | Surface | {class} |\n\
         | Primary invariant | {invariant} |\n\
         | Property | {property} |\n\
         | Mode | {mode} |\n\
         | Synthetic evidence | {synthetic} |\n\n\
         ## Invariants\n\n\
         | Invariant | Verdict | Evidence |\n\
         |---|---|---|\n\
         {rows}\n\
         ## Counts\n\n\
         | Measure | Value |\n\
         |---|---|\n\
         | Documents read | {documents} |\n\
         | Components evaluated | {components} |\n\
         | Relationships evaluated | {relationships} |\n\
         | Invariants decided | {decided} |\n\
         | Invariants without deciding evidence | {undecided} |\n\
         | Violations retained | {violations} |\n\
         | Registry, model-hub, OCI or Git fetches | 0 |\n\
         | Remote signature or transparency-log requests | 0 |\n\
         | Signatures or attestations issued | 0 |\n\
         | Artifacts, models or archives executed or extracted | 0 |\n\
         | State changes | 0 |\n\
         | External egress bytes | 0 |\n\
         | Verdict | {verdict} |\n\n\
         {reason}\n\n\
         Supply-chain trust relation: an inventory is not trust, a component name is not a \
         component identity, a version string is not an immutable artifact, a digest is not \
         provenance, provenance being present is not provenance being trusted, a valid signature \
         is not an approved signer, a declared dependency is not an observed one, the same name \
         and version is not the same artifact, a component URL is not authorization to fetch it, \
         and an external agent appearing in an inventory is not authorization to communicate \
         with it.\n\n\
         Scope: this run read local bill-of-materials, provenance and attestation documents \
         under the recorded conditions. No package registry, model hub, container registry, Git \
         host, transparency log, signing service, key server or vulnerability database was \
         contacted; no signature or attestation was issued; no artifact, model, archive or code \
         named in an imported document was executed, loaded or extracted. Licence compliance, \
         PII, copyright, bias and fairness were not assessed and are out of scope. It does not \
         establish that the supply chain is secure, and no result here should be read as a claim \
         of universal security.\n",
        scenario = result.scenario_id,
        class = result.class.as_str(),
        invariant = result.primary_invariant.as_str(),
        property = result.property_id,
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
    let result = run_scenario(&scenario, adapter.as_ref(), &mut ledger)?;
    let evidence = build_evidence(&scenario, &result, OffsetDateTime::now_utc())?;

    validate_output_dir(&args.output_dir).map_err(SupplyChainError::invalid)?;
    fs::create_dir_all(&args.output_dir).map_err(|error| {
        SupplyChainError::invalid(format!("output directory ({})", error.kind()))
    })?;

    write_json(
        &args.output_dir.join("supply-chain-security-result.json"),
        &result,
    )?;
    write_json(
        &args
            .output_dir
            .join("supply-chain-security-invariants.json"),
        &result.outcomes,
    )?;
    write_json(
        &args.output_dir.join("supply-chain-security-evidence.json"),
        &evidence,
    )?;

    let summary = render_summary(&result);
    assert_summary_is_bounded(&summary)?;
    fs::write(args.output_dir.join("summary.md"), summary.as_bytes())
        .map_err(|error| SupplyChainError::invalid(format!("summary ({})", error.kind())))?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(match result.verdict {
        Verdict::Pass => SUCCESS,
        Verdict::Fail | Verdict::Inconclusive => PARTIAL,
        Verdict::Error => SCANNER_ERROR,
    })
}

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), SupplyChainError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    assert_bytes_are_secret_safe(&bytes)?;
    fs::write(path, bytes)
        .map_err(|error| SupplyChainError::invalid(format!("artifact ({})", error.kind())))?;
    Ok(())
}

/// Refuse to write an artifact that carries a canary or credential.
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
    // Anchored on shape, so an honest sentence about bearer credentials stays
    // writable while a real one is refused.
    if dare_supply_chain_security::schema::contains_bearer_credential(&text.to_ascii_lowercase()) {
        return Err(SupplyChainError::refusal(
            "refusing to write an artifact containing sensitive content".to_owned(),
        ));
    }
    Ok(())
}

/// Refuse to write a summary that overstates what was validated.
fn assert_summary_is_bounded(summary: &str) -> Result<(), SupplyChainError> {
    let lowered = summary.to_lowercase();
    for forbidden in [
        "supply chain is secure",
        "supply-chain secure",
        "fully verified",
        "fully trusted",
        "no substitution possible",
        "substitution impossible",
        "tamper-proof",
        "provably authentic",
        "all components verified",
    ] {
        // The scope paragraph denies each of these in a sentence containing the
        // phrase, so a bare occurrence is what is refused rather than any
        // mention.
        let denied = format!("not establish that the {forbidden}");
        if lowered.contains(forbidden) && !lowered.contains(&denied) {
            return Err(SupplyChainError::refusal(format!(
                "refusing to write a summary that claims more than was validated: `{forbidden}`"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_built_in_corpus_id_resolves_to_a_scenario() {
        let scenario = load_scenario("SUPPLY-LAB-004").expect("resolves");
        assert_eq!(scenario.scenario_id, "SUPPLY-LAB-004");
        assert!(!scenario.description.is_empty());
    }

    #[test]
    fn an_unknown_corpus_id_is_refused_rather_than_running_empty() {
        // Running as though it had named nothing would report a clean verdict
        // for a vector nobody exercised.
        let error = load_scenario("SUPPLY-LAB-999").expect_err("must be refused");
        assert!(error.to_string().contains("SUPPLY-LAB-999"));
    }

    #[test]
    fn a_path_shaped_corpus_id_is_refused() {
        for hostile in ["../../etc/passwd", "SUPPLY/../LAB"] {
            assert!(load_scenario(hostile).is_err(), "`{hostile}` was accepted");
        }
    }

    #[test]
    fn a_flag_from_another_mode_is_a_usage_error() {
        // Silently dropping it would run a different evidence set than the
        // operator asked for.
        let scenario = load_scenario("SUPPLY-LAB-004").expect("resolves");
        let args = SupplyChainArgs {
            scenario: "SUPPLY-LAB-004".to_owned(),
            mode: SupplyChainModeArg::Simulated,
            evidence_dir: Some(PathBuf::from(".")),
            capture: None,
            manifest: None,
            output_dir: PathBuf::from("out"),
            json: false,
        };
        assert!(
            build_adapter(&args, &scenario).is_err(),
            "a stray flag was ignored"
        );
    }

    #[test]
    fn replay_requires_a_manifest_the_capture_did_not_supply() {
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
        let Err(error) = build_adapter(&args, &scenario) else {
            panic!("replay without a manifest was accepted");
        };
        assert!(error.to_string().contains("--manifest"));
    }

    #[test]
    fn the_summary_of_a_clean_run_is_bounded() {
        let scenario = load_scenario("SUPPLY-LAB-001").expect("resolves");
        let mut ledger = AdmissionLedger::new();
        let result = run_scenario(&scenario, &CorpusAdapter, &mut ledger).expect("runs");
        let summary = render_summary(&result);
        assert_summary_is_bounded(&summary).expect("bounded");
        assert!(summary.contains("does not establish that the supply chain is secure"));
        assert!(summary.contains("| Registry, model-hub, OCI or Git fetches | 0 |"));
    }

    #[test]
    fn an_overstated_summary_is_refused() {
        assert!(assert_summary_is_bounded("the supply chain is secure").is_err());
        assert!(assert_summary_is_bounded("all components verified").is_err());
    }

    #[test]
    fn an_artifact_carrying_a_credential_is_not_written() {
        assert!(assert_bytes_are_secret_safe(b"{\"note\":\"ghp_example\"}").is_err());
        assert!(assert_bytes_are_secret_safe(b"{\"note\":\"a purl is inert\"}").is_ok());
    }

    #[test]
    fn the_command_exposes_no_fetch_or_credential_flag() {
        // The narrow surface, asserted over the rendered help rather than over
        // the struct, because the help is what an operator reads and what a
        // reviewer checks.
        use clap::CommandFactory;
        #[derive(clap::Parser)]
        struct Wrapper {
            #[command(flatten)]
            inner: SupplyChainArgs,
        }
        let rendered = Wrapper::command()
            .render_long_help()
            .to_string()
            .to_lowercase();
        for forbidden in [
            "--registry",
            "--fetch",
            "--download",
            "--resolve",
            "--model-hub",
            "--oci",
            "--git",
            "--rekor",
            "--fulcio",
            "--transparency-log",
            "--sign",
            "--key",
            "--private-key",
            "--token",
            "--remote",
            "--command",
            "--extract",
        ] {
            assert!(
                !rendered.contains(&format!("{forbidden} ")),
                "the command exposes `{forbidden}`"
            );
        }
    }
}
