//! `run_remote` and `replay_capture` (BLUEPRINT §5.2).
//!
//! `run_remote` verifies the authorization, drives each planned scenario's
//! live pass through one gateway, then decides every verdict from the
//! finished capture. `replay_capture` runs the same verdict pass over a
//! stored capture and opens no socket. Because the verdict pass reads only
//! the capture, both produce byte-identical results (O-03).

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use dare_security_evidence::{SecurityEvidence, Verdict};
use time::OffsetDateTime;

use crate::audit::AuditRecord;
use crate::authorization::{verify, Authorization, ScenarioDigests};
use crate::canonical::digest;
use crate::capture::Capture;
use crate::credential::Scrubber;
use crate::engines::{
    self, a2a, block_on, mcp_auth, multi_turn, prompt_injection, EngineOutcome, SharedGateway,
    Sources,
};
use crate::error::{RemoteError, Result};
use crate::evidence::{retag, ObservedWindow, Provenance};
use crate::gateway::{EgressGateway, TrustRoots};
use crate::ledger::OutputLedger;
use crate::limits::Limits;
use crate::origin::Origin;
use crate::plan::{EngineKind, PlannedRun, RemotePlan};
use crate::protocol::{Method, Protocol};
use crate::result::{render_artifacts, Artifact, Header, RemoteResult};

/// A planned scenario, loaded from the engine's own sources.
#[derive(Debug, Clone)]
pub enum LoadedRun {
    PromptInjection(Box<prompt_injection::Loaded>),
    MultiTurn(Box<multi_turn::Loaded>),
    A2a(Box<a2a::Loaded>),
    McpAuth(Box<mcp_auth::Loaded>),
}

impl LoadedRun {
    pub fn load(sources: &Sources, run: &PlannedRun) -> Result<LoadedRun> {
        let id = run.scenario_id.as_str();
        Ok(match run.engine {
            EngineKind::PromptInjection => {
                LoadedRun::PromptInjection(Box::new(prompt_injection::load(sources, id)?))
            }
            EngineKind::MultiTurn => LoadedRun::MultiTurn(Box::new(multi_turn::load(id)?)),
            EngineKind::A2a => LoadedRun::A2a(Box::new(a2a::load(id)?)),
            EngineKind::McpAuth => LoadedRun::McpAuth(Box::new(mcp_auth::load(sources, id)?)),
        })
    }

    pub fn digest(&self) -> &str {
        match self {
            LoadedRun::PromptInjection(l) => &l.digest,
            LoadedRun::MultiTurn(l) => &l.digest,
            LoadedRun::A2a(l) => &l.digest,
            LoadedRun::McpAuth(l) => &l.digest,
        }
    }

    /// Which plan protocols can carry this engine.
    fn carried_by(&self, protocol: Protocol) -> bool {
        matches!(
            (self, protocol),
            (LoadedRun::PromptInjection(_), Protocol::DareConversation)
                | (
                    LoadedRun::MultiTurn(_),
                    Protocol::DareConversation | Protocol::A2a
                )
                | (LoadedRun::A2a(_), Protocol::A2a)
                | (LoadedRun::McpAuth(_), Protocol::Mcp)
        )
    }
}

/// Rule 14's digest source: the engine's own digest of the scenario it would
/// run. A multi-turn run whose graph digests differ from the scenario's
/// answers with a digest that can never match.
pub struct EngineDigests<'a> {
    pub sources: &'a Sources,
}

impl ScenarioDigests for EngineDigests<'_> {
    fn digest_of(&self, run: &PlannedRun) -> Result<String> {
        let loaded = LoadedRun::load(self.sources, run)?;
        if let LoadedRun::MultiTurn(l) = &loaded {
            if l.graph_digests != run.graph_digests {
                return Ok(String::from("graph-digests-differ"));
            }
        }
        Ok(loaded.digest().to_owned())
    }
}

/// A run's product.
pub struct RemoteRun {
    pub result: RemoteResult,
    pub capture: Capture,
    pub audit: AuditRecord,
    pub evidence: Vec<SecurityEvidence>,
    scrubber: Scrubber,
}

impl RemoteRun {
    /// The six artifacts, scrubbed and charged to a fresh output ledger.
    pub fn artifacts(&self) -> Result<Vec<Artifact>> {
        let mut ledger = OutputLedger::new(self.scrubber.clone());
        render_artifacts(
            &mut ledger,
            &self.result,
            &self.capture,
            &self.evidence,
            &self.audit,
        )
    }
}

/// Resolve an A2A policy file under `--policy-dir`, refusing any path that
/// could leave it.
pub fn policy_path(policy_dir: Option<&Path>, run: &PlannedRun) -> Result<Option<PathBuf>> {
    if run.engine != EngineKind::A2a {
        return Ok(None);
    }
    let dir = policy_dir.ok_or(RemoteError::Refused(
        "a plan with an A2A run needs --policy-dir",
    ))?;
    let name = run.a2a_policy_file.as_deref().ok_or(RemoteError::Refused(
        "an A2A run must name its a2a_policy_file",
    ))?;
    let relative = Path::new(name);
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
        || !name.ends_with("-policy.json")
    {
        return Err(RemoteError::Refused(
            "an A2A policy file is a plain `*-policy.json` name under --policy-dir",
        ));
    }
    let root = dir
        .canonicalize()
        .map_err(|_| RemoteError::Refused("--policy-dir is not readable"))?;
    let path = root
        .join(relative)
        .canonicalize()
        .map_err(|_| RemoteError::Refused("the A2A policy file is not readable"))?;
    if !path.starts_with(&root) || !path.is_file() {
        return Err(RemoteError::Refused(
            "the A2A policy file resolves outside --policy-dir",
        ));
    }
    Ok(Some(path))
}

fn load_all(
    sources: &Sources,
    plan: &RemotePlan,
    policy_dir: Option<&Path>,
) -> Result<Vec<(LoadedRun, Option<PathBuf>)>> {
    plan.runs
        .iter()
        .map(|run| {
            let loaded = LoadedRun::load(sources, run)?;
            if !loaded.carried_by(plan.protocol) {
                return Err(RemoteError::Refused(
                    "a planned engine cannot run over the plan's protocol",
                ));
            }
            Ok((loaded, policy_path(policy_dir, run)?))
        })
        .collect()
}

fn env_lookup(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The live pass of one scenario.
fn live_one(
    gateway: &SharedGateway,
    handle: &tokio::runtime::Handle,
    loaded: &LoadedRun,
    protocol: Protocol,
    methods: &BTreeSet<Method>,
) -> Result<()> {
    match loaded {
        LoadedRun::PromptInjection(l) => prompt_injection::live(gateway.clone(), handle.clone(), l),
        LoadedRun::MultiTurn(l) => {
            let version = if protocol == Protocol::A2a && methods.contains(&Method::A2aAgentCardGet)
            {
                let card = block_on(handle, async {
                    let mut g = gateway.lock().await;
                    let scenario_ref = crate::capture::ScenarioRef {
                        engine: EngineKind::MultiTurn,
                        scenario_id: l.case.scenario.id.as_str().to_owned(),
                        conversation_id: None,
                        node_id: None,
                        step: None,
                    };
                    crate::protocol::a2a::fetch_card(&mut g, scenario_ref).await
                })?;
                card.1
                    .as_ref()
                    .map(crate::protocol::a2a::declared_version)
                    .unwrap_or_else(|_| "1.0.0".to_owned())
            } else {
                "1.0.0".to_owned()
            };
            multi_turn::live(gateway.clone(), handle.clone(), l, protocol, &version)
        }
        LoadedRun::A2a(l) => block_on(handle, async {
            let mut g = gateway.lock().await;
            a2a::live(&mut g, l, methods).await
        }),
        LoadedRun::McpAuth(l) => block_on(handle, async {
            let mut g = gateway.lock().await;
            mcp_auth::live(&mut g, l, methods).await
        }),
    }
}

/// The verdict pass over a finished capture: shared by both entry points.
#[allow(clippy::too_many_arguments)]
fn decide(
    auth: &Authorization,
    plan: &RemotePlan,
    capture: &Capture,
    audit: &AuditRecord,
    loaded: &[(LoadedRun, Option<PathBuf>)],
    work_root: &Path,
    scrubber: Scrubber,
) -> Result<RemoteRun> {
    let planned: Vec<(EngineKind, String)> = plan
        .runs
        .iter()
        .map(|r| (r.engine, r.scenario_id.as_str().to_owned()))
        .collect();
    let origin = Origin::parse(&plan.origin)?.as_string();
    let mut outcomes: Vec<(String, EngineOutcome)> = Vec::new();
    for (position, (run, policy)) in loaded.iter().enumerate() {
        let unfinished = engines::unfinished(capture, position, &planned);
        let outcome = match run {
            LoadedRun::PromptInjection(l) => prompt_injection::verdict(capture, l, unfinished)?,
            LoadedRun::MultiTurn(l) => multi_turn::verdict(capture, l, plan.protocol, unfinished)?,
            LoadedRun::A2a(l) => {
                let endpoint = auth
                    .endpoints
                    .a2a_rpc
                    .as_deref()
                    .ok_or(RemoteError::Refused(
                        "the authorization names no A2A endpoint",
                    ))?;
                let policy = policy
                    .as_deref()
                    .ok_or(RemoteError::Refused("an A2A run needs its policy file"))?;
                let work = work_root
                    .join(".remote-work")
                    .join(&capture.capture_id)
                    .join(position.to_string());
                a2a::verdict(capture, l, endpoint, policy, &work, unfinished)?
            }
            LoadedRun::McpAuth(l) => {
                let endpoint = auth.endpoints.mcp.as_deref().ok_or(RemoteError::Refused(
                    "the authorization names no MCP endpoint",
                ))?;
                mcp_auth::verdict(capture, l, &format!("{origin}{endpoint}"), unfinished)?
            }
        };
        outcomes.push((run.digest().to_owned(), outcome));
    }
    let _ = std::fs::remove_dir_all(work_root.join(".remote-work"));

    let plan_digest = digest(plan)?;
    let provenance = Provenance {
        authorization_id: auth.authorization_id.to_string(),
        authorization_digest: capture.authorization_digest.clone(),
        plan_digest: plan_digest.clone(),
        origin: capture.origin.clone(),
        capture_id: capture.capture_id.clone(),
        capture_digest: digest(capture)?,
        observed_window: ObservedWindow {
            from: capture.started_at.clone(),
            to: capture.ended_at.clone(),
        },
    };
    let mut evidence = Vec::new();
    for (_, outcome) in &outcomes {
        for record in &outcome.evidence {
            evidence.push(retag(
                record.clone(),
                &provenance,
                &outcome.self_reported_fields,
                &outcome.not_observable,
            )?);
        }
    }
    let header = Header {
        authorization_id: auth.authorization_id.as_str(),
        authorization_digest: &capture.authorization_digest,
        plan_id: plan.plan_id.as_str(),
        plan_digest: &plan_digest,
        protocol: plan.protocol,
    };
    let result = RemoteResult::build(header, capture, audit, &outcomes)?;
    Ok(RemoteRun {
        result,
        capture: capture.clone(),
        audit: audit.clone(),
        evidence,
        scrubber,
    })
}

/// Verify, run live, then decide from the capture.
///
/// Must run on a multi-thread tokio runtime (the adapters use
/// `block_in_place`).
#[allow(clippy::too_many_arguments)]
pub fn run_remote(
    auth: &Authorization,
    plan: &RemotePlan,
    confirm_origin: &str,
    policy_dir: Option<&Path>,
    now: OffsetDateTime,
    trust: TrustRoots,
    handle: tokio::runtime::Handle,
    sources: &Sources,
    work_root: &Path,
) -> Result<RemoteRun> {
    run_remote_lowered(
        auth,
        plan,
        confirm_origin,
        policy_dir,
        now,
        trust,
        handle,
        sources,
        work_root,
        &Limits::default(),
    )
}

/// As `run_remote`, with limits lowered further after verification (the
/// CLI's `--max-*` flags). The plan is untouched, so replay still binds.
#[allow(clippy::too_many_arguments)]
pub fn run_remote_lowered(
    auth: &Authorization,
    plan: &RemotePlan,
    confirm_origin: &str,
    policy_dir: Option<&Path>,
    now: OffsetDateTime,
    trust: TrustRoots,
    handle: tokio::runtime::Handle,
    sources: &Sources,
    work_root: &Path,
    lower: &Limits,
) -> Result<RemoteRun> {
    run_remote_stoppable(
        auth,
        plan,
        confirm_origin,
        policy_dir,
        now,
        trust,
        handle,
        sources,
        work_root,
        lower,
        Arc::new(AtomicBool::new(false)),
    )
}

/// As `run_remote_lowered`, with an operator stop flag the caller sets
/// (the CLI's Ctrl-C). Once set, no further request leaves; the run ends
/// with `KILL_SWITCH` and its artifacts and audit record are still produced.
#[allow(clippy::too_many_arguments)]
pub fn run_remote_stoppable(
    auth: &Authorization,
    plan: &RemotePlan,
    confirm_origin: &str,
    policy_dir: Option<&Path>,
    now: OffsetDateTime,
    trust: TrustRoots,
    handle: tokio::runtime::Handle,
    sources: &Sources,
    work_root: &Path,
    lower: &Limits,
    stop: Arc<AtomicBool>,
) -> Result<RemoteRun> {
    let mut verified = verify(
        auth,
        plan,
        confirm_origin,
        now,
        &EngineDigests { sources },
        &env_lookup,
    )?;
    verified.lower_limits(lower)?;
    let loaded = load_all(sources, plan, policy_dir)?;
    let gateway =
        EgressGateway::new(&mut verified, plan, confirm_origin, trust)?.with_operator_stop(stop);
    finish_run(auth, plan, loaded, gateway, handle, work_root)
}

/// As `run_remote`, with a gateway the caller built (lab tests inject a
/// resolver or a stop flag).
#[cfg(any(test, feature = "lab"))]
pub fn run_with_gateway(
    auth: &Authorization,
    plan: &RemotePlan,
    policy_dir: Option<&Path>,
    gateway: EgressGateway,
    handle: tokio::runtime::Handle,
    sources: &Sources,
    work_root: &Path,
) -> Result<RemoteRun> {
    let loaded = load_all(sources, plan, policy_dir)?;
    finish_run(auth, plan, loaded, gateway, handle, work_root)
}

fn finish_run(
    auth: &Authorization,
    plan: &RemotePlan,
    loaded: Vec<(LoadedRun, Option<PathBuf>)>,
    gateway: EgressGateway,
    handle: tokio::runtime::Handle,
    work_root: &Path,
) -> Result<RemoteRun> {
    let scrubber = gateway.scrubber();
    let shared: SharedGateway = Arc::new(tokio::sync::Mutex::new(gateway));
    let planned: Vec<(EngineKind, String)> = plan
        .runs
        .iter()
        .map(|r| (r.engine, r.scenario_id.as_str().to_owned()))
        .collect();
    for (position, (run, policy)) in loaded.iter().enumerate() {
        if block_on(&handle, async { shared.lock().await.stop_reason() }).is_some() {
            break;
        }
        match live_one(&shared, &handle, run, plan.protocol, &plan.methods) {
            // A stop (budget, kill, window, egress refusal) ends the live
            // pass; the verdict pass reports it from the capture.
            Ok(())
            | Err(
                RemoteError::Killed(_)
                | RemoteError::BudgetExhausted(_)
                | RemoteError::Egress(_)
                | RemoteError::Transport(_),
            ) => {}
            Err(other) => return Err(other),
        }
        if plan.stop_on_first_fail && position + 1 < loaded.len() {
            let snapshot = block_on(&handle, async { shared.lock().await.capture_snapshot() });
            let single = [(run.clone(), policy.clone())];
            let outcome = decide_one(
                auth,
                plan,
                &snapshot,
                &single,
                &planned[position..=position],
                work_root,
            )?;
            if outcome == Verdict::Fail {
                block_on(&handle, async { shared.lock().await.stop_first_fail() });
            }
        }
    }
    let gateway = Arc::try_unwrap(shared)
        .map_err(|_| RemoteError::Serialization("gateway still shared"))?
        .into_inner();
    let (capture, audit) = gateway.finish(None)?;
    decide(auth, plan, &capture, &audit, &loaded, work_root, scrubber)
}

/// The engine verdict of one scenario over a partial capture (first-failure
/// check only; never reported).
fn decide_one(
    auth: &Authorization,
    plan: &RemotePlan,
    snapshot: &Capture,
    loaded: &[(LoadedRun, Option<PathBuf>)],
    _planned: &[(EngineKind, String)],
    work_root: &Path,
) -> Result<Verdict> {
    let origin = Origin::parse(&plan.origin)?.as_string();
    let (run, policy) = &loaded[0];
    let outcome = match run {
        LoadedRun::PromptInjection(l) => prompt_injection::verdict(snapshot, l, None)?,
        LoadedRun::MultiTurn(l) => multi_turn::verdict(snapshot, l, plan.protocol, None)?,
        LoadedRun::A2a(l) => {
            let endpoint = auth.endpoints.a2a_rpc.as_deref().unwrap_or("/");
            let Some(policy) = policy.as_deref() else {
                return Ok(Verdict::Inconclusive);
            };
            a2a::verdict(
                snapshot,
                l,
                endpoint,
                policy,
                &work_root.join(".remote-work").join("first-fail"),
                None,
            )?
        }
        LoadedRun::McpAuth(l) => {
            let endpoint = auth.endpoints.mcp.as_deref().unwrap_or("/");
            mcp_auth::verdict(snapshot, l, &format!("{origin}{endpoint}"), None)?
        }
    };
    Ok(outcome.engine_verdict)
}

/// Recompute a run's result from its stored capture and audit. Opens no
/// socket and needs no credential or open window.
pub fn replay_capture(
    auth: &Authorization,
    plan: &RemotePlan,
    capture: &Capture,
    audit: &AuditRecord,
    policy_dir: Option<&Path>,
    sources: &Sources,
    work_root: &Path,
) -> Result<RemoteRun> {
    capture.verify()?;
    audit.verify(capture)?;
    let auth_digest = digest(auth)?;
    if plan.authorization_digest != auth_digest || capture.authorization_digest != auth_digest {
        return Err(RemoteError::Refused(
            "the capture was not made under this authorization",
        ));
    }
    if capture.plan_digest != digest(plan)? {
        return Err(RemoteError::Refused(
            "the capture was not made for this plan",
        ));
    }
    if Origin::parse(&capture.origin)? != Origin::parse(&plan.origin)? {
        return Err(RemoteError::Refused(
            "the capture's origin is not the plan's",
        ));
    }
    let digests = EngineDigests { sources };
    for run in &plan.runs {
        if digests.digest_of(run)? != run.scenario_digest {
            return Err(RemoteError::Refused(
                "a planned scenario no longer has its authorized digest",
            ));
        }
    }
    let loaded = load_all(sources, plan, policy_dir)?;
    decide(
        auth,
        plan,
        capture,
        audit,
        &loaded,
        work_root,
        Scrubber::new(None),
    )
}
