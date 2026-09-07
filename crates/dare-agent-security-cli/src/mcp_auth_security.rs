//! `dare-agent-security validate mcp-auth-security` (Cycle 018).
//!
//! Bounded, local, offline validation of one MCP 2026 authentication or
//! authorization scenario: protocol and routing binding, Protected Resource
//! Metadata, authorization-server and issuer boundaries, token resource and
//! audience, PKCE, redirect and state, scope step-up, client-registration
//! trust, credential separation, self-reported identity metadata, or the
//! binding between a permit and the operation finally performed.
//!
//! The flag surface is deliberately narrow. There is no `--url`, `--endpoint`,
//! `--authorization-server`, `--token-endpoint`, `--jwks-url`, `--issuer-url`,
//! `--client-secret`, `--access-token`, `--refresh-token`,
//! `--authorization-code`, `--private-key`, `--cookie`, `--remote` or
//! `--command` option, because Cycle 018 has no HTTP client, OAuth client, JWT
//! verifier or execution path for such a flag to reach. No environment variable
//! can supply one either: this command reads none.
//!
//! Modes are the three approved local ones. Nothing here performs a login,
//! exchanges an authorization code, fetches metadata or a key set, introspects
//! a token, registers a client, or calls a protected resource. Tokens are
//! synthetic claim *structures* — an issuer, an audience, a resource and a
//! recorded validity state — never signed artifacts, and a validity state is a
//! description of what a verifier reported, not a verification performed here.

use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args, ValueEnum};
use dare_mcp_auth_security::canonical::bind;
use dare_mcp_auth_security::corpus::{builtin_corpus_root, load_corpus, McpAuthCorpus};
use dare_mcp_auth_security::evidence_bridge::build_evidence;
use dare_mcp_auth_security::harness::{HarnessAdapter, HarnessMode};
use dare_mcp_auth_security::local_synthetic::LocalSyntheticAdapter;
use dare_mcp_auth_security::model::{McpAuthCorpusEntry, McpAuthScenario};
use dare_mcp_auth_security::replay::ReplayAdapter;
use dare_mcp_auth_security::result::{run_scenario, McpAuthSecurityResult};
use dare_mcp_auth_security::schema::{enforce_document_size, validate_scenario_document};
use dare_mcp_auth_security::simulated::SimulatedAdapter;
use dare_mcp_auth_security::source::ScenarioClass;
use dare_mcp_auth_security::{McpAuthSecurityError, Verdict};
use serde_json::Value;
use time::OffsetDateTime;

use crate::ci_output::validate_output_dir;
use crate::exit_code::{PARTIAL, SCANNER_ERROR, SUCCESS, UNSUPPORTED_TARGET};

/// Approved local modes. There is no remote, live or provider variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum McpAuthSecurityModeArg {
    /// Evaluate a sanitized local trace without contacting anything.
    Replay,
    /// Deterministic scenario-derived observations.
    Simulated,
    /// Controlled local synthetic execution through the Cycle 009 substrate.
    LocalSynthetic,
}

impl From<McpAuthSecurityModeArg> for HarnessMode {
    fn from(value: McpAuthSecurityModeArg) -> Self {
        match value {
            McpAuthSecurityModeArg::Replay => Self::Replay,
            McpAuthSecurityModeArg::Simulated => Self::Simulated,
            McpAuthSecurityModeArg::LocalSynthetic => Self::LocalSynthetic,
        }
    }
}

/// `validate mcp-auth-security` options.
#[derive(Debug, Args)]
#[command(after_help = MCP_AUTH_SECURITY_AFTER_HELP)]
pub struct McpAuthSecurityArgs {
    /// Scenario file path, or a built-in scenario id such as `MCP-AUTH-LAB-001`.
    #[arg(long, value_name = "PATH-OR-ID")]
    pub scenario: String,

    /// Execution mode. All modes are local and offline.
    #[arg(long, value_enum, default_value = "simulated")]
    pub mode: McpAuthSecurityModeArg,

    /// Sanitized local authorization trace. Replay mode only.
    #[arg(long, value_name = "PATH")]
    pub trace: Option<PathBuf>,

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

pub const MCP_AUTH_SECURITY_AFTER_HELP: &str = "\
Exit codes (`validate mcp-auth-security`):
  0  no MCP 2026 authentication/authorization invariant violation was observed
  1  harness or environment error
  2  a deterministic invariant violation was observed, or evidence was inconclusive
  3  usage error or safety refusal

Modes are local and offline: replay, simulated, local-synthetic.
This capability has no endpoint, issuer, authorization-server, token, JWKS,
client-secret, private-key, cookie or registration flag, and it reads no
credential from the environment. No production MCP endpoint, live OAuth or OIDC
flow, browser login, authorization-code exchange, real bearer or refresh token,
live JWKS, token introspection, Protected Resource Metadata retrieval,
authorization-server metadata retrieval, CIMD or dynamic client registration,
external identity provider, remote protected resource or upstream API is
involved, and no state change or external egress occurs.
Tokens are synthetic claim structures with a recorded validity state; nothing
here signs, verifies, introspects or exchanges a credential.
Protocol metadata is not authenticated identity, a token being present is not a
token being valid, a valid token is not a correctly audienced one, and a correct
token is not authorization for an operation that changed after the permit.
DPoP, workload identity federation, ID-JAG, standardized token exchange and
Enterprise-Managed Authorization are forward-looking and are not requirements
here; COAZ and COAZ-MCP remain drafts, and openid/authzen#603 remains an open
proposal.
A PASS is scoped to the tested vectors under the recorded conditions, and is
never a claim that MCP authentication or authorization is secure.
";

fn scenarios_root() -> PathBuf {
    PathBuf::from("crates/dare-mcp-auth-security/tests/fixtures/scenarios")
}

/// Resolve `--scenario` as a built-in id or a file path.
fn load_scenario(spec: &str) -> Result<McpAuthScenario, McpAuthSecurityError> {
    let path = if spec.ends_with(".json") || spec.contains('/') || spec.contains('\\') {
        PathBuf::from(spec)
    } else {
        // Built-in id. The pattern keeps this from becoming a path expression.
        if !spec
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(McpAuthSecurityError::invalid(
                "scenario id must be uppercase alphanumeric with dashes",
            ));
        }
        scenarios_root().join(format!("{}.json", spec.to_ascii_lowercase()))
    };

    let raw = fs::read(&path).map_err(|err| {
        McpAuthSecurityError::invalid(format!("scenario unavailable ({}): {err}", path.display()))
    })?;
    enforce_document_size(&raw, "scenario")?;
    let value: Value = serde_json::from_slice(&raw).map_err(|err| {
        McpAuthSecurityError::schema(format!("scenario is not valid JSON: {err}"))
    })?;
    validate_scenario_document(&value)?;
    let scenario: McpAuthScenario = serde_json::from_value(value)?;
    scenario.validate()?;
    Ok(scenario)
}

fn build_adapter(
    args: &McpAuthSecurityArgs,
    scenario: &McpAuthScenario,
    trials: u32,
) -> Result<Box<dyn HarnessAdapter>, McpAuthSecurityError> {
    let mode: HarnessMode = args.mode.into();

    if mode != HarnessMode::Replay && args.trace.is_some() {
        return Err(McpAuthSecurityError::invalid(
            "--trace is only valid with --mode replay",
        ));
    }

    match mode {
        HarnessMode::Replay => {
            let path = args
                .trace
                .as_ref()
                .ok_or_else(|| McpAuthSecurityError::invalid("--mode replay requires --trace"))?;
            let adapter = ReplayAdapter::from_path(path)?;
            // Refuse a trace recorded against a different scenario before a
            // single observation is read from it. A trace is evidence of what
            // happened; it is not the authority that says what was approved,
            // and matching only on `scenario_id` would let it become one.
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

fn require_lab(scenario: &McpAuthScenario) -> Result<(), McpAuthSecurityError> {
    if scenario.lab.is_none() {
        return Err(McpAuthSecurityError::invalid(
            "simulated and local-synthetic modes require the scenario to declare a lab \
             reference behavior",
        ));
    }
    Ok(())
}

/// The corpus is the built-in one, and there is no flag to point it elsewhere.
///
/// Cycle 017 accepted a `--corpus` override; the approved flag list for this
/// command does not, so the root is fixed here rather than being reachable from
/// the command line.
fn builtin_corpus() -> Result<McpAuthCorpus, McpAuthSecurityError> {
    load_corpus(&builtin_corpus_root())
}

/// State of one authorization surface for this run.
///
/// "not tested" and "passed" are different answers. A scenario exercises
/// exactly one surface; the other five are reported as untested rather than
/// quietly counted as holding.
fn surface_state(result: &McpAuthSecurityResult, surface: ScenarioClass) -> &'static str {
    if result.class == surface {
        "TESTED"
    } else {
        "NOT TESTED"
    }
}

/// Render the operator summary with bounded claim wording.
fn render_summary(result: &McpAuthSecurityResult) -> String {
    let violations = result.violations().len();
    let inconclusive = result
        .trials
        .iter()
        .filter(|trial| trial.verdict == Verdict::Inconclusive)
        .count();

    format!(
        "# DARE MCP 2026 Authentication and Authorization Validation\n\n\
         | Field | Value |\n\
         |---|---|\n\
         | Scenario | {scenario} |\n\
         | Corpus vector | {corpus} |\n\
         | Property | {property} |\n\
         | Invariant | {invariant} |\n\
         | Invariant surface | {class} |\n\
         | Declared protocol revision | {revision} |\n\
         | Expected resource | {resource} |\n\
         | Mode | {mode} |\n\
         | Synthetic observations | {synthetic} |\n\n\
         ## Surfaces\n\n\
         | Surface | State |\n\
         |---|---|\n\
         | PROTOCOL_BINDING | {protocol} |\n\
         | RESOURCE_AUTHORIZATION | {resource_authorization} |\n\
         | TOKEN_BINDING | {token} |\n\
         | FLOW_INTEGRITY | {flow} |\n\
         | SCOPE_AND_REGISTRATION | {scope} |\n\
         | CREDENTIAL_AND_IDENTITY | {credential} |\n\n\
         ## Counts\n\n\
         | Measure | Value |\n\
         |---|---|\n\
         | Scenarios | 1 |\n\
         | Trials planned | {planned} |\n\
         | Trials executed | {executed} |\n\
         | Requests observed | {requests} |\n\
         | Violations observed | {violations} |\n\
         | Inconclusive trials | {inconclusive} |\n\
         | Authorization-code exchanges | 0 |\n\
         | Metadata documents retrieved | 0 |\n\
         | Tokens verified against a key set | 0 |\n\
         | Clients registered | 0 |\n\
         | Protected-resource calls | 0 |\n\
         | State changes | 0 |\n\
         | External egress bytes | 0 |\n\
         | Stop reason | {stop} |\n\
         | Verdict | {verdict} |\n\n\
         {claim}\n\n\
         Authorization trust relation: protocol metadata is not authenticated identity, a token \
         being present is not a token being valid, a valid token is not one issued for this \
         resource and audience, a correct token is not authorization for an operation that \
         changed after the permit, and the credential a caller presented to the MCP server is \
         not the credential the server may present upstream.\n\n\
         Scope: this run exercised a finite set of local synthetic vectors under the recorded \
         conditions. No production MCP endpoint, live OAuth or OIDC flow, browser login, \
         authorization-code exchange, real bearer or refresh token, real cookie, client secret, \
         private key, live JWKS, token introspection, Protected Resource Metadata retrieval, \
         authorization-server metadata retrieval, CIMD or dynamic client registration, external \
         identity provider, remote protected resource or upstream API was contacted. Token \
         claims were synthetic structures with a recorded validity state; nothing here signed, \
         verified, introspected or exchanged a credential. DPoP, workload identity federation, \
         ID-JAG, standardized token exchange and Enterprise-Managed Authorization were not \
         assessed and are not requirements here. It does not establish that MCP authentication \
         or authorization holds in general, and no result here should be read as a claim of \
         universal security.\n",
        scenario = result.scenario_id,
        corpus = result.corpus_id.as_deref().unwrap_or("(none)"),
        property = result.property_id.as_str(),
        invariant = result.invariant.as_str(),
        class = result.class.as_str(),
        revision = result.protocol_revision,
        resource = result.expected_resource,
        mode = result.mode.as_str(),
        synthetic = if result.synthetic { "yes" } else { "no" },
        protocol = surface_state(result, ScenarioClass::ProtocolBinding),
        resource_authorization = surface_state(result, ScenarioClass::ResourceAuthorization),
        token = surface_state(result, ScenarioClass::TokenBinding),
        flow = surface_state(result, ScenarioClass::FlowIntegrity),
        scope = surface_state(result, ScenarioClass::ScopeAndRegistration),
        credential = surface_state(result, ScenarioClass::CredentialAndIdentity),
        planned = result.trials_planned,
        executed = result.trials_executed,
        requests = result.requests(),
        violations = violations,
        inconclusive = inconclusive,
        stop = result.stop_reason.as_str(),
        verdict = result.verdict.as_str(),
        claim = result.bounded_claim(),
    )
}

pub fn run_mcp_auth_security(args: McpAuthSecurityArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(error) if error.is_refusal() => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error @ (McpAuthSecurityError::Invalid(_) | McpAuthSecurityError::Schema(_))) => {
            eprintln!("{error}");
            UNSUPPORTED_TARGET
        }
        Err(error) => {
            eprintln!("{error}");
            SCANNER_ERROR
        }
    }
}

fn run_inner(args: McpAuthSecurityArgs) -> Result<i32, McpAuthSecurityError> {
    let scenario = load_scenario(&args.scenario)?;

    // The corpus is loaded whenever the scenario names a vector, in every mode.
    // A substituted vector must be refused even when the run itself would have
    // replayed a trace.
    //
    // `resolve` is what makes that refusal happen. A scenario may name the
    // corpus as a whole, in which case loading it has already verified every
    // pinned entry digest and there is no single vector to bind; or it may name
    // one entry, which is then bound and pinned. Naming a vector the corpus does
    // not contain is neither, and is refused rather than treated as naming
    // nothing.
    let entry: Option<McpAuthCorpusEntry> = match scenario.vector.as_ref() {
        Some(_) => builtin_corpus()?
            .resolve(scenario.vector.as_ref())?
            .cloned(),
        None => None,
    };

    // Refuse a substituted request, resource, issuer, token, claim set or
    // policy before anything is observed.
    let binding = bind(&scenario)?;

    let plan = dare_mcp_auth_security::trials::TrialPlan::from_scenario(&scenario)?
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

    validate_output_dir(&args.output_dir).map_err(McpAuthSecurityError::invalid)?;
    fs::create_dir_all(&args.output_dir)?;

    write_json(
        &args.output_dir.join("mcp-auth-security-result.json"),
        &result,
    )?;
    write_json(
        &args.output_dir.join("mcp-auth-security-trials.json"),
        &result.trials,
    )?;
    write_json(
        &args.output_dir.join("mcp-auth-security-evidence.json"),
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

fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), McpAuthSecurityError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    assert_bytes_are_secret_safe(&bytes)?;
    fs::write(path, bytes)?;
    Ok(())
}

/// Refuse to write an artifact that carries a canary or credential.
fn assert_bytes_are_secret_safe(bytes: &[u8]) -> Result<(), McpAuthSecurityError> {
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
            return Err(McpAuthSecurityError::refusal(
                "refusing to write an artifact containing sensitive content",
            ));
        }
    }
    // Anchored on shape, so an honest sentence about bearer credentials stays
    // writable while a real one is refused.
    if dare_mcp_auth_security::schema::contains_bearer_credential(&text.to_ascii_lowercase()) {
        return Err(McpAuthSecurityError::refusal(
            "refusing to write an artifact containing sensitive content",
        ));
    }
    Ok(())
}

/// Refuse to write a summary that overstates what was validated.
fn assert_summary_is_bounded(summary: &str) -> Result<(), McpAuthSecurityError> {
    let lowered = summary.to_lowercase();
    for forbidden in [
        "mcp auth secure",
        "mcp is secure",
        "authentication is secure",
        "authorization is secure",
        "oauth secure",
        "fully authenticated",
        "fully protected",
        "token misuse impossible",
        "no token misuse possible",
        "cannot be impersonated",
        "immune",
        "guaranteed secure",
        "spec compliant",
        "rfc compliant",
        "authzen compliant",
        "oauth 2.1 compliant",
    ] {
        if lowered.contains(forbidden) {
            return Err(McpAuthSecurityError::refusal(format!(
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
        args: McpAuthSecurityArgs,
    }

    fn parse(argv: &[&str]) -> Result<Harness, clap::Error> {
        Harness::try_parse_from(std::iter::once("harness").chain(argv.iter().copied()))
    }

    #[test]
    fn the_prohibited_endpoint_and_credential_flags_do_not_exist() {
        // Every flag the approval forbids by name, plus the ones that would
        // each imply their own client. A flag that parsed would mean a code
        // path able to use it, which is the thing that must not exist.
        for flag in [
            "--url",
            "--endpoint",
            "--authorization-server",
            "--token-endpoint",
            "--jwks-url",
            "--issuer-url",
            "--client-secret",
            "--access-token",
            "--refresh-token",
            "--authorization-code",
            "--private-key",
            "--cookie",
            "--remote",
            "--command",
            "--introspection-endpoint",
            "--registration-endpoint",
            "--resource-metadata-url",
            "--client-id",
            "--redirect-uri",
            "--scope",
            "--audience",
            "--token",
            "--bearer",
            "--idp",
        ] {
            let result = parse(&[
                "--scenario",
                "MCP-AUTH-LAB-001",
                "--output-dir",
                "out",
                flag,
                "value",
            ]);
            assert!(result.is_err(), "`{flag}` was accepted");
        }
    }

    #[test]
    fn the_command_exposes_exactly_the_six_approved_flags() {
        // The complement of the test above. Listing what may exist catches a
        // flag added later that nobody thought to forbid by name.
        let approved = [
            "scenario",
            "mode",
            "trace",
            "trials",
            "output-dir",
            "json",
            "help",
        ];
        for argument in Harness::command().get_arguments() {
            let name = argument.get_long().unwrap_or_default();
            assert!(
                approved.contains(&name),
                "`--{name}` is not an approved flag"
            );
        }
    }

    #[test]
    fn the_mode_enum_admits_only_the_three_local_modes() {
        for mode in ["replay", "simulated", "local-synthetic"] {
            parse(&[
                "--scenario",
                "MCP-AUTH-LAB-001",
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
            "http",
            "production",
            "oauth",
            "interactive",
            "browser",
        ] {
            assert!(
                parse(&[
                    "--scenario",
                    "MCP-AUTH-LAB-001",
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
            "MCP-AUTH-LAB-001",
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
                    "MCP-AUTH-LAB-001",
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
    fn the_help_text_names_what_this_command_never_reaches() {
        let help = Harness::command().render_long_help().to_string();
        for absent in [
            "live OAuth",
            "browser login",
            "authorization-code exchange",
            "live JWKS",
            "token introspection",
            "dynamic client registration",
            "identity provider",
        ] {
            assert!(help.contains(absent), "the help omits {absent}");
        }
        assert!(help.contains("Protocol metadata is not authenticated identity"));
        assert!(help.contains("never a claim that MCP authentication"));
    }

    #[test]
    fn the_help_text_keeps_the_forward_looking_work_out_of_the_requirements() {
        // A reader must not come away believing DPoP or workload identity
        // federation was assessed, or that an open proposal is normative.
        let help = Harness::command().render_long_help().to_string();
        assert!(help.contains("DPoP"));
        assert!(help.contains("forward-looking"));
        assert!(help.contains("open"));
    }

    #[test]
    fn a_scenario_id_cannot_become_a_path_expression() {
        for hostile in [
            "../../etc/passwd",
            "..",
            "MCP-AUTH-LAB-001/../../secret",
            "mcp-auth-lab-001",
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
            "the server is MCP Auth Secure",
            "token misuse impossible",
            "the deployment is spec compliant",
            "the client cannot be impersonated",
            "authorization is secure under all inputs",
        ] {
            assert!(
                assert_summary_is_bounded(hostile).is_err(),
                "`{hostile}` was allowed"
            );
        }

        assert!(assert_summary_is_bounded(
            "No MCP 2026 authentication/authorization hardening invariant violation was observed \
             for the tested vectors under the recorded conditions."
        )
        .is_ok());
    }

    #[test]
    fn an_artifact_carrying_a_canary_or_credential_is_refused() {
        for hostile in [
            "the response carried DARE-SYNTHETIC-CANARY-MCPAUTH01",
            "the upstream call carried sk-live-000000000000000000000000",
            "-----BEGIN PRIVATE KEY-----",
            "Authorization: Bearer abcdefghijklmnopqrstuvwx",
            "the token was eyJhbGciOiJIUzI1NiJ9",
        ] {
            assert!(
                assert_bytes_are_secret_safe(hostile.as_bytes()).is_err(),
                "`{hostile}` was allowed into an artifact"
            );
        }

        // An honest sentence about the boundary stays writable.
        assert!(assert_bytes_are_secret_safe(
            b"an inbound bearer credential must not become the authority for an upstream call"
        )
        .is_ok());
    }

    /// Load the built-in lab by absolute path.
    ///
    /// `scenarios_root` is workspace-relative because that is the working
    /// directory the command runs in; a unit test runs from its own crate
    /// directory, so it resolves the same file itself rather than changing the
    /// command's behavior to suit the test.
    fn built_in_lab(lab: &str) -> McpAuthScenario {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../dare-mcp-auth-security/tests/fixtures/scenarios")
            .join(format!("{}.json", lab.to_ascii_lowercase()));
        load_scenario(&path.to_string_lossy()).expect("the built-in lab loads")
    }

    fn rendered(lab: &str) -> String {
        let scenario = built_in_lab(lab);
        let plan =
            dare_mcp_auth_security::trials::TrialPlan::from_scenario(&scenario).expect("plan");
        let result = run_scenario(&scenario, None, &SimulatedAdapter::new(), plan).expect("runs");
        render_summary(&result)
    }

    #[test]
    fn a_summary_reports_every_surface_and_marks_the_untested_ones() {
        // The failure mode: five surfaces nobody exercised rendering as absent,
        // which reads as nothing to report rather than nothing tried.
        let summary = rendered("MCP-AUTH-LAB-001");

        for surface in [
            "PROTOCOL_BINDING",
            "RESOURCE_AUTHORIZATION",
            "TOKEN_BINDING",
            "FLOW_INTEGRITY",
            "SCOPE_AND_REGISTRATION",
            "CREDENTIAL_AND_IDENTITY",
        ] {
            assert!(summary.contains(surface), "{surface} is missing");
        }
        assert!(summary.contains("NOT TESTED"));
        assert!(summary.contains("| Authorization-code exchanges | 0 |"));
        assert!(summary.contains("| Metadata documents retrieved | 0 |"));
        assert!(summary.contains("| Tokens verified against a key set | 0 |"));
        assert!(summary.contains("| External egress bytes | 0 |"));
        assert_summary_is_bounded(&summary).expect("the rendered summary is bounded");
    }

    #[test]
    fn the_summary_states_the_distinctions_it_was_built_to_keep_apart() {
        // A reader holding this one file has no other way to learn that a
        // present token is not a valid one, or that a valid token is not a
        // correctly audienced one.
        let summary = rendered("MCP-AUTH-LAB-001");
        assert!(summary.contains("protocol metadata is not authenticated identity"));
        assert!(summary.contains("not a token being valid"));
        assert!(summary.contains("this resource and audience"));
        assert!(summary.contains("changed after the permit"));
        assert!(summary.contains("not the credential the server may present upstream"));
    }

    #[test]
    fn an_inconclusive_run_says_so_and_never_reads_as_a_pass() {
        // Lab 035 observes nothing the invariant needs. The summary has to make
        // that visibly different from a clean run.
        let summary = rendered("MCP-AUTH-LAB-035");
        assert!(summary.contains("| Verdict | INCONCLUSIVE |"));
        assert!(summary.contains("not a pass"));
        assert!(!summary.contains(
            "No MCP 2026 authentication/authorization hardening invariant \
                                   violation was observed"
        ));
    }

    fn trace_fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../dare-mcp-auth-security/tests/fixtures/traces")
            .join(format!("{name}.json"))
    }

    fn args_for(
        lab: &str,
        mode: McpAuthSecurityModeArg,
        trace: Option<&str>,
    ) -> McpAuthSecurityArgs {
        McpAuthSecurityArgs {
            scenario: lab.to_owned(),
            mode,
            trace: trace.map(trace_fixture),
            trials: None,
            output_dir: PathBuf::from("out"),
            json: false,
        }
    }

    #[test]
    fn a_trace_is_only_meaningful_in_replay_mode() {
        // Accepting `--trace` alongside a staged mode would let an operator
        // believe a recording was used when it was silently ignored.
        let scenario = built_in_lab("MCP-AUTH-LAB-001");
        for mode in [
            McpAuthSecurityModeArg::Simulated,
            McpAuthSecurityModeArg::LocalSynthetic,
        ] {
            let args = args_for("MCP-AUTH-LAB-001", mode, Some("trace-lab-001"));
            assert!(
                build_adapter(&args, &scenario, 3).is_err(),
                "{mode:?} accepted a trace it would not have read"
            );
        }

        let args = args_for("MCP-AUTH-LAB-001", McpAuthSecurityModeArg::Replay, None);
        assert!(
            build_adapter(&args, &scenario, 3).is_err(),
            "replay mode ran without a trace"
        );
    }

    #[test]
    fn the_cli_refuses_a_trace_that_widens_the_operation_under_the_same_scenario_id() {
        // The Cycle 017 defect, checked at the command boundary rather than only
        // in the crate. A trace is evidence of what happened, never the
        // authority for what was approved.
        let scenario = built_in_lab("MCP-AUTH-LAB-001");
        let args = args_for(
            "MCP-AUTH-LAB-001",
            McpAuthSecurityModeArg::Replay,
            Some("trace-unbound-operation"),
        );
        let err = build_adapter(&args, &scenario, 3)
            .err()
            .expect("an unbound trace must be refused");
        assert!(err.to_string().contains("operation"));

        // And a trace that is properly bound still runs.
        let args = args_for(
            "MCP-AUTH-LAB-001",
            McpAuthSecurityModeArg::Replay,
            Some("trace-lab-001"),
        );
        assert!(build_adapter(&args, &scenario, 3).is_ok());
    }

    #[test]
    fn a_summary_of_a_violated_run_still_carries_no_credential_or_canary() {
        // The report of a breach is the place most likely to quote what
        // breached. Lab 027 forwards the inbound credential upstream; the
        // summary must name the finding without reproducing the credential.
        let summary = rendered("MCP-AUTH-LAB-027");
        assert!(summary.contains("| Verdict | FAIL |"));
        assert_summary_is_bounded(&summary).expect("a failing summary is still bounded");
        assert!(!summary.contains("DARE-SYNTHETIC-CANARY-"));
    }
}
