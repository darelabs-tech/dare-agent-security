//! `dare-agent-security validate identity-security` (Cycle 015).
//!
//! Bounded, local, offline validation of one identity, privilege, delegation,
//! tenant or authorization-binding scenario.
//!
//! The flag surface is deliberately narrow. There is no `--url`, `--endpoint`,
//! `--issuer`, `--jwks`, `--token`, `--bearer`, `--client-secret`, `--api-key`,
//! `--pdp-url`, `--authzen-url`, `--remote` or `--command` option, because
//! Cycle 015 has no provider, authorization server or execution path for such a
//! flag to reach. No environment variable can supply a credential either: this
//! command reads none. Modes are the three approved local ones, and a
//! structured operation is observed, never dispatched.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use dare_identity_security::canonical::bind;
use dare_identity_security::corpus::{builtin_corpus_root, load_corpus, IdentityCorpus};
use dare_identity_security::evidence_bridge::build_evidence;
use dare_identity_security::harness::{HarnessAdapter, HarnessMode};
use dare_identity_security::local_synthetic::LocalSyntheticAdapter;
use dare_identity_security::model::{
    IdentityCorpusEntry, IdentityInvariantType, IdentitySecurityScenario,
};
use dare_identity_security::replay::ReplayAdapter;
use dare_identity_security::result::{run_scenario, IdentitySecurityResult};
use dare_identity_security::schema::{enforce_document_size, validate_scenario_document};
use dare_identity_security::simulated::SimulatedAdapter;
use dare_identity_security::source::ScenarioClass;
use dare_identity_security::trials::TrialPlan;
use dare_identity_security::{IdentitySecurityError, Verdict};
use serde_json::Value;
use time::OffsetDateTime;

use crate::ci_output::validate_output_dir;
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

/// Approved local modes. There is no remote, provider or live-identity variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum IdentitySecurityModeArg {
    /// Evaluate a sanitized local trace without contacting any provider.
    Replay,
    /// Deterministic scenario-derived observations.
    Simulated,
    /// Controlled local synthetic execution through the Cycle 009 substrate.
    LocalSynthetic,
}

impl From<IdentitySecurityModeArg> for HarnessMode {
    fn from(value: IdentitySecurityModeArg) -> Self {
        match value {
            IdentitySecurityModeArg::Replay => Self::Replay,
            IdentitySecurityModeArg::Simulated => Self::Simulated,
            IdentitySecurityModeArg::LocalSynthetic => Self::LocalSynthetic,
        }
    }
}

/// `validate identity-security` options.
#[derive(Debug, Args)]
#[command(after_help = IDENTITY_SECURITY_AFTER_HELP)]
pub struct IdentitySecurityArgs {
    /// Scenario file path, or a built-in scenario id such as `IDENTITY-LAB-001`.
    #[arg(long, value_name = "PATH-OR-ID")]
    pub scenario: String,

    /// Execution mode. All modes are local and offline.
    #[arg(long, value_enum, default_value = "simulated")]
    pub mode: IdentitySecurityModeArg,

    /// Sanitized local identity trace. Replay mode only.
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

pub const IDENTITY_SECURITY_AFTER_HELP: &str = "\
Exit codes (`validate identity-security`):
  0  no identity-security invariant violation was observed for the tested vectors
  1  harness or environment error
  2  a deterministic invariant violation was observed, or evidence was inconclusive
  3  usage error or safety refusal

Modes are local and offline: replay, simulated, local-synthetic.
This capability has no identity provider, OAuth server, PDP, AuthZEN endpoint,
MCP client or credential flag, and it reads no credential from the environment.
Tokens are never parsed or validated; authority is modelled declaratively.
Structured operations are observed, never dispatched: no delete, share, payment
or cross-tenant read is performed by this command, and no real tenant data is
touched to demonstrate a boundary crossing.
A PASS is scoped to the tested vectors under the recorded conditions, and is
never a claim that identity, authorization or privilege handling is secure.
";

fn scenarios_root() -> PathBuf {
    PathBuf::from("crates/dare-identity-security/tests/fixtures/scenarios")
}

/// Resolve `--scenario` as a built-in id or a file path.
fn load_scenario(spec: &str) -> Result<IdentitySecurityScenario, IdentitySecurityError> {
    let path = if spec.ends_with(".json") || spec.contains('/') || spec.contains('\\') {
        PathBuf::from(spec)
    } else {
        // Built-in id. The pattern keeps this from becoming a path expression.
        if !spec
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(IdentitySecurityError::invalid(
                "scenario id must be uppercase alphanumeric with dashes",
            ));
        }
        scenarios_root().join(format!("{}.json", spec.to_ascii_lowercase()))
    };

    let raw = fs::read(&path).map_err(|err| {
        IdentitySecurityError::invalid(format!("scenario unavailable ({}): {err}", path.display()))
    })?;
    enforce_document_size(&raw, "scenario")?;
    let value: Value = serde_json::from_slice(&raw).map_err(|err| {
        IdentitySecurityError::schema(format!("scenario is not valid JSON: {err}"))
    })?;
    validate_scenario_document(&value)?;
    let scenario: IdentitySecurityScenario = serde_json::from_value(value)?;
    scenario.validate()?;
    Ok(scenario)
}

fn load_corpus_for(args: &IdentitySecurityArgs) -> Result<IdentityCorpus, IdentitySecurityError> {
    let root = args.corpus.clone().unwrap_or_else(builtin_corpus_root);
    load_corpus(&root)
}

fn build_adapter(
    args: &IdentitySecurityArgs,
    scenario: &IdentitySecurityScenario,
    trials: u32,
) -> Result<Box<dyn HarnessAdapter>, IdentitySecurityError> {
    let mode: HarnessMode = args.mode.into();

    if mode != HarnessMode::Replay && args.trace.is_some() {
        return Err(IdentitySecurityError::invalid(
            "--trace is only valid with --mode replay",
        ));
    }

    match mode {
        HarnessMode::Replay => {
            let path = args
                .trace
                .as_ref()
                .ok_or_else(|| IdentitySecurityError::invalid("--mode replay requires --trace"))?;
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

fn require_lab(scenario: &IdentitySecurityScenario) -> Result<(), IdentitySecurityError> {
    if scenario.lab.is_none() {
        return Err(IdentitySecurityError::invalid(
            "simulated and local-synthetic modes require the scenario to declare a lab \
             reference behavior",
        ));
    }
    Ok(())
}

/// State of one identity-security surface for this run.
///
/// "not applicable" and "not tested" are different answers, and neither is
/// "passed". A scenario exercises exactly one surface; the other four are
/// reported as untested rather than quietly counted as holding.
fn surface_state(result: &IdentitySecurityResult, surface: ScenarioClass) -> &'static str {
    if result.class == surface {
        "TESTED"
    } else {
        "NOT TESTED"
    }
}

/// Whether the invariant that was evaluated belongs to this surface.
fn invariant_surface(invariant: IdentityInvariantType) -> ScenarioClass {
    invariant.surface()
}

/// Render the operator summary with bounded claim wording.
fn render_summary(result: &IdentitySecurityResult) -> String {
    let violations = result.violations().len();
    let inconclusive = result
        .trials
        .iter()
        .filter(|trial| trial.verdict == Verdict::Inconclusive)
        .count();

    format!(
        "# DARE Identity, Privilege and Delegation Validation\n\n\
         | Field | Value |\n\
         |---|---|\n\
         | Scenario | {scenario} |\n\
         | Corpus vector | {corpus} |\n\
         | Property | {property} |\n\
         | Invariant | {invariant} |\n\
         | Invariant surface | {invariant_surface} |\n\
         | Source boundary | {source} ({trust}) |\n\
         | Principal set | {principal_set} |\n\
         | Initiating principal | {initiating} |\n\
         | Effective principal | {effective} |\n\
         | Agent principal | {agent} |\n\
         | Delegated subject | {subject} |\n\
         | Resource owner | {owner} |\n\
         | Tenant | {tenant} |\n\
         | Mode | {mode} |\n\
         | Synthetic observations | {synthetic} |\n\n\
         ## Surfaces\n\n\
         | Surface | State |\n\
         |---|---|\n\
         | PRINCIPAL_BINDING | {principal_binding} |\n\
         | DELEGATION | {delegation} |\n\
         | PRIVILEGE | {privilege} |\n\
         | TENANT_RESOURCE | {tenant_resource} |\n\
         | AUTHORIZATION_BINDING | {authorization_binding} |\n\n\
         ## Counts\n\n\
         | Measure | Value |\n\
         |---|---|\n\
         | Scenarios | 1 |\n\
         | Trials planned | {planned} |\n\
         | Trials executed | {executed} |\n\
         | Operations observed | {operations} |\n\
         | Delegation edges observed | {depth} |\n\
         | Violations observed | {violations} |\n\
         | Inconclusive trials | {inconclusive} |\n\
         | State changes | 0 |\n\
         | External egress bytes | 0 |\n\
         | Stop reason | {stop} |\n\
         | Verdict | {verdict} |\n\n\
         {claim}\n\n\
         Authority relation: effective authority must stay within the delegated or source \
         authority ceiling. The presence of a service, workload or technical credential is \
         capability availability, not delegated authority.\n\n\
         Scope: this run exercised a finite local corpus of synthetic identities under the \
         recorded conditions. Operations were observed and never dispatched, no identity \
         provider or authorization server was contacted, no token was parsed or validated, and \
         no real tenant data was accessed. It does not establish that identity, delegation or \
         authorization handling holds in general, and no result here should be read as a claim \
         of universal identity or authorization security.\n",
        scenario = result.scenario_id,
        corpus = result.corpus_id.as_deref().unwrap_or("(none)"),
        property = result.property_id,
        invariant = result.invariant.as_str(),
        invariant_surface = invariant_surface(result.invariant).as_str(),
        source = result.source_kind.as_str(),
        trust = result.source_trust.as_str(),
        principal_set = result.principal_set_id,
        initiating = result.initiating_principal_id,
        effective = result.effective_principal_id,
        agent = result.agent_principal_id.as_deref().unwrap_or("(none)"),
        subject = result.delegated_subject_id.as_deref().unwrap_or("(none)"),
        owner = result.resource_owner_id.as_deref().unwrap_or("(none)"),
        tenant = result.tenant_id.as_deref().unwrap_or("(none)"),
        mode = result.mode.as_str(),
        synthetic = if result.synthetic { "yes" } else { "no" },
        principal_binding = surface_state(result, ScenarioClass::PrincipalBinding),
        delegation = surface_state(result, ScenarioClass::Delegation),
        privilege = surface_state(result, ScenarioClass::Privilege),
        tenant_resource = surface_state(result, ScenarioClass::TenantResource),
        authorization_binding = surface_state(result, ScenarioClass::AuthorizationBinding),
        planned = result.trials_planned,
        executed = result.trials_executed,
        operations = result.operations(),
        depth = result
            .max_delegation_depth()
            .map(|depth| depth.to_string())
            .unwrap_or_else(|| "none observed".to_owned()),
        violations = violations,
        inconclusive = inconclusive,
        stop = result.stop_reason.as_str(),
        verdict = result.verdict.as_str(),
        claim = result.bounded_claim(),
    )
}

pub fn run_identity_security(args: IdentitySecurityArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(error) if error.is_refusal() => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error @ (IdentitySecurityError::Invalid(_) | IdentitySecurityError::Schema(_))) => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error) => {
            eprintln!("{error}");
            SCANNER_ERROR
        }
    }
}

fn run_inner(args: IdentitySecurityArgs) -> Result<i32, IdentitySecurityError> {
    let scenario = load_scenario(&args.scenario)?;

    // The corpus is loaded whenever the scenario names a vector, in every mode.
    // A substituted vector must be refused even when the run itself would have
    // replayed a trace.
    let entry: Option<IdentityCorpusEntry> = match scenario.vector.as_ref() {
        Some(vector) => {
            let corpus = load_corpus_for(&args)?;
            Some(corpus.require(&vector.corpus_id)?.clone())
        }
        None => None,
    };

    // Refuse a substituted principal set, authority, chain, resource or policy
    // before anything is observed.
    let binding = bind(&scenario)?;

    let plan = TrialPlan::from_scenario(&scenario)?.with_trial_override(args.trials)?;
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

    validate_output_dir(&args.output_dir).map_err(IdentitySecurityError::invalid)?;
    fs::create_dir_all(&args.output_dir)?;

    write_json(
        &args.output_dir.join("identity-security-result.json"),
        &result,
    )?;
    write_json(
        &args.output_dir.join("identity-security-trials.json"),
        &result.trials,
    )?;
    write_json(
        &args.output_dir.join("identity-security-evidence.json"),
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

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), IdentitySecurityError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    assert_bytes_are_secret_safe(&bytes)?;
    fs::write(path, bytes)?;
    Ok(())
}

/// Refuse to write an artifact that carries a canary or credential.
fn assert_bytes_are_secret_safe(bytes: &[u8]) -> Result<(), IdentitySecurityError> {
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
            return Err(IdentitySecurityError::refusal(
                "refusing to write an artifact containing sensitive content",
            ));
        }
    }
    // Anchored on shape, so an honest sentence about bearer credentials stays
    // writable while a real one is refused.
    if dare_identity_security::schema::contains_bearer_credential(&text.to_ascii_lowercase()) {
        return Err(IdentitySecurityError::refusal(
            "refusing to write an artifact containing sensitive content",
        ));
    }
    Ok(())
}

/// Refuse to write a summary that overstates what was validated.
fn assert_summary_is_bounded(summary: &str) -> Result<(), IdentitySecurityError> {
    let lowered = summary.to_lowercase();
    for forbidden in [
        "identity secure",
        "authorization secure",
        "no privilege escalation possible",
        "fully protected",
        "immune",
        "guaranteed secure",
        "cannot be escalated",
        "cannot be impersonated",
        "authzen compliant",
        "coaz compliant",
    ] {
        if lowered.contains(forbidden) {
            return Err(IdentitySecurityError::refusal(format!(
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
        args: IdentitySecurityArgs,
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
                "trials",
            ]
        );
    }

    #[test]
    fn no_remote_provider_or_credential_flag_exists() {
        // These are not merely undocumented: there is no code path behind them,
        // and adding one would need a design change, not a flag.
        let flags = long_flags();
        for forbidden in [
            "url",
            "endpoint",
            "issuer",
            "jwks",
            "jwks-uri",
            "token",
            "bearer",
            "client-secret",
            "api-key",
            "pdp-url",
            "authzen-url",
            "remote",
            "command",
            "provider",
            "host",
            "server",
        ] {
            assert!(
                !flags.iter().any(|flag| flag == forbidden),
                "--{forbidden} must not exist"
            );
        }
    }

    #[test]
    fn only_the_three_local_modes_can_be_selected() {
        for mode in ["replay", "simulated", "local-synthetic"] {
            Wrapper::try_parse_from([
                "x",
                "--scenario",
                "IDENTITY-LAB-001",
                "--output-dir",
                "out",
                "--mode",
                mode,
            ])
            .unwrap_or_else(|err| panic!("{mode} must parse: {err}"));
        }
        for mode in ["live", "live-idp", "oauth", "remote", "production", "pdp"] {
            assert!(
                Wrapper::try_parse_from([
                    "x",
                    "--scenario",
                    "IDENTITY-LAB-001",
                    "--output-dir",
                    "out",
                    "--mode",
                    mode,
                ])
                .is_err(),
                "--mode {mode} must be rejected"
            );
        }
    }

    #[test]
    fn the_trial_ceiling_cannot_be_raised_from_the_command_line() {
        for trials in ["0", "11", "100"] {
            assert!(
                Wrapper::try_parse_from([
                    "x",
                    "--scenario",
                    "IDENTITY-LAB-001",
                    "--output-dir",
                    "out",
                    "--trials",
                    trials,
                ])
                .is_err(),
                "--trials {trials} must be rejected"
            );
        }
        Wrapper::try_parse_from([
            "x",
            "--scenario",
            "IDENTITY-LAB-001",
            "--output-dir",
            "out",
            "--trials",
            "10",
        ])
        .expect("the hard maximum itself is allowed");
    }

    #[test]
    fn a_scenario_id_cannot_become_a_path_expression() {
        for hostile in ["../../../etc/passwd", "a/b", "..", "IDENTITY LAB"] {
            assert!(
                load_scenario(hostile).is_err(),
                "`{hostile}` must be refused"
            );
        }
    }

    #[test]
    fn an_unbounded_claim_is_refused_before_it_is_written() {
        for claim in [
            "The system is Identity Secure.",
            "No Privilege Escalation Possible here.",
            "Fully Protected against delegation abuse.",
            "The agent is Immune to confused-deputy attacks.",
            "DARE is AuthZEN compliant.",
        ] {
            let err = assert_summary_is_bounded(claim).expect_err("must be refused");
            assert!(err.is_refusal(), "{claim}");
        }
    }

    #[test]
    fn an_artifact_carrying_a_credential_is_refused_before_it_is_written() {
        for hostile in [
            "sk-live-0123456789abcdef",
            "Bearer abcdefghijklmnopqrstuvwxyz012345",
            "-----BEGIN PRIVATE KEY-----",
            "DARE-SYNTHETIC-CANARY-IDENT01",
        ] {
            assert!(
                assert_bytes_are_secret_safe(hostile.as_bytes()).is_err(),
                "`{hostile}` must be refused"
            );
        }
        // The boundary has to stay describable.
        assert_bytes_are_secret_safe(
            b"this run required no bearer token and stored no credential material",
        )
        .expect("prose about credentials is not a credential");
    }

    #[test]
    fn the_after_help_states_the_boundary_rather_than_implying_a_guarantee() {
        assert!(IDENTITY_SECURITY_AFTER_HELP.contains("observed, never dispatched"));
        assert!(IDENTITY_SECURITY_AFTER_HELP.contains("no identity provider"));
        assert!(IDENTITY_SECURITY_AFTER_HELP.contains("never a claim"));
        let lowered = IDENTITY_SECURITY_AFTER_HELP.to_lowercase();
        for banned in ["immune", "fully protected", "guaranteed"] {
            assert!(!lowered.contains(banned), "{banned}");
        }
    }
}
