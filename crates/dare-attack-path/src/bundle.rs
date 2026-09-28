//! Artifact bundles and input binding (BLUEPRINT §4.4, tasks 014–016).
//!
//! A bundle is one engine run: exactly one known result file, its evidence
//! file, and the inputs the result pins under `inputs/`. Binding recomputes
//! every pinned digest with the owning engine's own public digest function
//! (AD-05) and refuses on the first mismatch, so a projector only ever reads
//! inputs the engine actually judged.
use std::path::Path;

use dare_a2a_security::{capture::A2aCapture, normalize::A2aEvidence, result::A2aSecurityResult};
use dare_identity_security::result::IdentitySecurityResult;
use dare_mcp_auth_security::{model::McpAuthScenario, result::McpAuthSecurityResult};
use dare_memory_security::result::MemorySecurityResult;
use dare_multi_turn_security::{result::MultiTurnResult, runner::ConversationRun};
use dare_prompt_injection::result::PromptInjectionResult;
use dare_rag_security::result::RagSecurityResult;
use dare_supply_chain_security::{
    normalize::SupplyChainEvidence, replay::SupplyChainCapture, result::SupplyChainSecurityResult,
};
use dare_tool_security::result::ToolSecurityResult;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{
    admit::{admit_dir, AdmittedDir},
    error::{Refusal, Result},
    evidence_index::EvidenceIndex,
    ids::{sha256_prefixed, EngineSlug, RunTag},
    load,
};

pub const REMOTE_RESULT_SCHEMA_JSON: &str =
    include_str!("../../../schemas/remote-validation/v1/result.schema.json");

/// (result file, engine, evidence file)
pub const BUNDLES: [(&str, EngineSlug, &str); 10] = [
    (
        "prompt-injection-result.json",
        EngineSlug::PromptInjection,
        "prompt-injection-evidence.json",
    ),
    (
        "tool-security-result.json",
        EngineSlug::Tool,
        "tool-security-evidence.json",
    ),
    (
        "identity-security-result.json",
        EngineSlug::Identity,
        "identity-security-evidence.json",
    ),
    (
        "memory-security-result.json",
        EngineSlug::Memory,
        "memory-security-evidence.json",
    ),
    (
        "rag-security-result.json",
        EngineSlug::Rag,
        "rag-security-evidence.json",
    ),
    (
        "mcp-auth-security-result.json",
        EngineSlug::McpAuth,
        "mcp-auth-security-evidence.json",
    ),
    (
        "supply-chain-security-result.json",
        EngineSlug::SupplyChain,
        "supply-chain-security-evidence.json",
    ),
    ("a2a-result.json", EngineSlug::A2a, "a2a-evidence.json"),
    (
        "multi-turn-result.json",
        EngineSlug::MultiTurn,
        "multi-turn-evidence.json",
    ),
    (
        "remote-result.json",
        EngineSlug::Remote,
        "remote-evidence.json",
    ),
];

pub const CONVERSATIONS_FILE: &str = "multi-turn-conversations.json";
pub const EVIDENCE_DIR: &str = "inputs/evidence";
pub const CAPTURE_FILE: &str = "inputs/capture.json";
pub const MANIFEST_FILE: &str = "inputs/manifest.json";
pub const POLICY_FILE: &str = "inputs/policy.json";

/// The engine data a projector reads, bound and validated.
///
/// Variant sizes differ widely, but there is one value per artifact directory
/// (at most 64), so boxing would only add indirection.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum RunData {
    PromptInjection {
        result: PromptInjectionResult,
    },
    Tool {
        result: ToolSecurityResult,
        scenario: dare_tool_security::model::ToolSecurityScenario,
    },
    Identity {
        result: IdentitySecurityResult,
        scenario: dare_identity_security::model::IdentitySecurityScenario,
    },
    Memory {
        result: MemorySecurityResult,
        scenario: dare_memory_security::model::MemorySecurityScenario,
    },
    Rag {
        result: RagSecurityResult,
        scenario: dare_rag_security::model::RagSecurityScenario,
    },
    McpAuth {
        result: McpAuthSecurityResult,
        scenario: McpAuthScenario,
    },
    SupplyChain {
        result: SupplyChainSecurityResult,
        evidence: SupplyChainEvidence,
    },
    A2a {
        result: A2aSecurityResult,
        evidence: A2aEvidence,
    },
    MultiTurn {
        result: MultiTurnResult,
        conversations: Vec<ConversationRun>,
    },
    Remote {
        runs: Vec<RemoteRun>,
    },
}

/// One `runs[i]` of a Cycle 022 result.
#[derive(Debug, Clone)]
pub struct RemoteRun {
    pub position: usize,
    pub verdict: dare_attack_graph::v2::GuardVerdict,
    pub scenario_digest: String,
    pub engine_result: Option<RemoteEngineResult>,
    /// An MCP-auth scenario bound from `inputs/run-<i>/scenario.json`.
    pub mcp_scenario: Option<McpAuthScenario>,
}

#[derive(Debug, Clone)]
pub enum RemoteEngineResult {
    PromptInjection(PromptInjectionResult),
    MultiTurn(MultiTurnResult),
    A2a(A2aSecurityResult),
    McpAuth(McpAuthSecurityResult),
}

#[derive(Debug, Clone)]
pub struct LoadedBundle {
    pub index: usize,
    pub engine: EngineSlug,
    pub run: RunTag,
    pub result_digest: String,
    pub evidence_digest: String,
    pub input_digests: Vec<String>,
    pub verified_inputs: Vec<String>,
    pub mode: String,
    pub synthetic: bool,
    pub dynamic_authorized: bool,
    pub evidence: EvidenceIndex,
    pub data: RunData,
}

fn invalid(index: usize, file: &'static str, reason: &'static str) -> Refusal {
    Refusal::InvalidDocument {
        index,
        file,
        reason,
    }
}

fn decode<T: DeserializeOwned>(index: usize, file: &'static str, value: &Value) -> Result<T> {
    serde_json::from_value(value.clone())
        .map_err(|_| invalid(index, file, "does not match the engine's result type").into())
}

fn mismatch(index: usize, input: &'static str) -> Refusal {
    Refusal::DigestMismatch { index, input }
}

fn same(
    computed: std::result::Result<String, impl Sized>,
    pinned: &str,
    index: usize,
    input: &'static str,
) -> Result<()> {
    match computed {
        Ok(digest) if digest == pinned => Ok(()),
        _ => Err(mismatch(index, input).into()),
    }
}

fn mode_string(value: &Value) -> String {
    value["mode"].as_str().unwrap_or("UNKNOWN").to_owned()
}

/// Detects the bundle kind: exactly one known result file.
pub fn detect(dir: &AdmittedDir) -> Result<(&'static str, EngineSlug, &'static str)> {
    let present: Vec<_> = BUNDLES
        .iter()
        .filter(|(file, _, _)| dir.has(file))
        .collect();
    match present.as_slice() {
        [one] => Ok(**one),
        _ => Err(Refusal::UnknownBundle { index: dir.index }.into()),
    }
}

pub fn load_bundle(index: usize, path: &Path) -> Result<LoadedBundle> {
    let dir = admit_dir(index, path)?;
    let (result_file, engine, evidence_file) = detect(&dir)?;
    let (result_bytes, result_value) = dir.read_json(result_file, "result")?;
    let (evidence_bytes, evidence_value) = dir.read_json(evidence_file, "evidence")?;
    let evidence = EvidenceIndex::build(index, engine, &evidence_value)?;
    let mut bundle = LoadedBundle {
        index,
        engine,
        run: RunTag::from_result_bytes(&result_bytes),
        result_digest: sha256_prefixed(&result_bytes),
        evidence_digest: sha256_prefixed(&evidence_bytes),
        input_digests: Vec::new(),
        verified_inputs: Vec::new(),
        mode: mode_string(&result_value),
        synthetic: result_value["synthetic"].as_bool().unwrap_or(false),
        dynamic_authorized: engine == EngineSlug::Remote,
        evidence,
        data: RunData::Remote { runs: vec![] },
    };
    bundle.data = match engine {
        EngineSlug::Tool => bind_tool(&dir, &result_value, &mut bundle)?,
        EngineSlug::Identity => bind_identity(&dir, &result_value, &mut bundle)?,
        EngineSlug::Memory => bind_memory(&dir, &result_value, &mut bundle)?,
        EngineSlug::Rag => bind_rag(&dir, &result_value, &mut bundle)?,
        EngineSlug::McpAuth => bind_mcp_auth(&dir, &result_value, &mut bundle)?,
        EngineSlug::SupplyChain => bind_supply_chain(&dir, &result_value, &mut bundle)?,
        EngineSlug::A2a => bind_a2a(&dir, &result_value, &mut bundle)?,
        EngineSlug::PromptInjection => bind_prompt_injection(&result_value, &mut bundle)?,
        EngineSlug::MultiTurn => bind_multi_turn(&dir, &result_value, &mut bundle)?,
        EngineSlug::Remote => bind_remote(&dir, &result_value, &mut bundle)?,
    };
    bundle.input_digests.sort();
    bundle.input_digests.dedup();
    Ok(bundle)
}

fn require_scenario(dir: &AdmittedDir) -> Result<()> {
    if dir.has(load::SCENARIO_FILE) {
        Ok(())
    } else {
        Err(Refusal::MissingInput {
            index: dir.index,
            input: "scenario",
        }
        .into())
    }
}

fn pin(bundle: &mut LoadedBundle, input: &str, digest: &str) {
    bundle.verified_inputs.push(input.to_owned());
    bundle.input_digests.push(digest.to_owned());
}

fn bind_tool(dir: &AdmittedDir, value: &Value, bundle: &mut LoadedBundle) -> Result<RunData> {
    use dare_tool_security::canonical::{scenario_digest, tool_surface_digest};
    let index = dir.index;
    let result: ToolSecurityResult = decode(index, "result", value)?;
    bundle.evidence.require_all(index, &result.evidence_ids)?;
    require_scenario(dir)?;
    let scenario = load::load_tool(dir, load::SCENARIO_FILE)?;
    same(
        scenario_digest(&scenario),
        &result.scenario_digest,
        index,
        "scenario",
    )?;
    same(
        tool_surface_digest(&scenario.tool_surface),
        &result.surface_digest,
        index,
        "tool surface",
    )?;
    pin(bundle, "scenario", &result.scenario_digest);
    pin(bundle, "tool surface", &result.surface_digest);
    Ok(RunData::Tool { result, scenario })
}

fn bind_identity(dir: &AdmittedDir, value: &Value, bundle: &mut LoadedBundle) -> Result<RunData> {
    use dare_identity_security::canonical::{
        delegation_chain_digest, digest, principal_set_digest, resource_context_digest,
    };
    let index = dir.index;
    let result: IdentitySecurityResult = decode(index, "result", value)?;
    bundle.evidence.require_all(index, &result.evidence_ids)?;
    require_scenario(dir)?;
    let scenario = load::load_identity(dir, load::SCENARIO_FILE)?;
    same(
        digest(&scenario),
        &result.scenario_digest,
        index,
        "scenario",
    )?;
    same(
        principal_set_digest(&scenario.principals),
        &result.principal_set_digest,
        index,
        "principal set",
    )?;
    pin(bundle, "scenario", &result.scenario_digest);
    pin(bundle, "principal set", &result.principal_set_digest);
    match (&scenario.delegation, &result.delegation_chain_digest) {
        (Some(chain), Some(pinned)) => {
            same(
                delegation_chain_digest(chain),
                pinned,
                index,
                "delegation chain",
            )?;
            pin(bundle, "delegation chain", pinned);
        }
        (None, None) => {}
        _ => return Err(mismatch(index, "delegation chain").into()),
    }
    match (&scenario.resource, &result.resource_context_digest) {
        (Some(resource), Some(pinned)) => {
            same(
                resource_context_digest(resource),
                pinned,
                index,
                "resource context",
            )?;
            pin(bundle, "resource context", pinned);
        }
        (None, None) => {}
        _ => return Err(mismatch(index, "resource context").into()),
    }
    Ok(RunData::Identity { result, scenario })
}

fn bind_memory(dir: &AdmittedDir, value: &Value, bundle: &mut LoadedBundle) -> Result<RunData> {
    use dare_memory_security::canonical::{digest, store_digest};
    let index = dir.index;
    let result: MemorySecurityResult = decode(index, "result", value)?;
    bundle.evidence.require_all(index, &result.evidence_ids)?;
    require_scenario(dir)?;
    let scenario = load::load_memory(dir, load::SCENARIO_FILE)?;
    same(
        digest(&scenario),
        &result.scenario_digest,
        index,
        "scenario",
    )?;
    same(
        store_digest(&scenario.store),
        &result.store_digest,
        index,
        "memory store",
    )?;
    pin(bundle, "scenario", &result.scenario_digest);
    pin(bundle, "memory store", &result.store_digest);
    Ok(RunData::Memory { result, scenario })
}

fn bind_rag(dir: &AdmittedDir, value: &Value, bundle: &mut LoadedBundle) -> Result<RunData> {
    use dare_rag_security::canonical::{digest, store_digest};
    let index = dir.index;
    let result: RagSecurityResult = decode(index, "result", value)?;
    bundle.evidence.require_all(index, &result.evidence_ids)?;
    require_scenario(dir)?;
    let scenario = load::load_rag(dir, load::SCENARIO_FILE)?;
    same(
        digest(&scenario),
        &result.scenario_digest,
        index,
        "scenario",
    )?;
    same(
        store_digest(&scenario.store),
        &result.store_digest,
        index,
        "document store",
    )?;
    pin(bundle, "scenario", &result.scenario_digest);
    pin(bundle, "document store", &result.store_digest);
    Ok(RunData::Rag { result, scenario })
}

fn bind_mcp_auth(dir: &AdmittedDir, value: &Value, bundle: &mut LoadedBundle) -> Result<RunData> {
    let index = dir.index;
    let result: McpAuthSecurityResult = decode(index, "result", value)?;
    bundle.evidence.require_all(index, &result.evidence_ids)?;
    require_scenario(dir)?;
    let scenario = load::load_mcp_auth(dir, load::SCENARIO_FILE)?;
    same(
        dare_mcp_auth_security::canonical::digest(&scenario),
        &result.scenario_digest,
        index,
        "scenario",
    )?;
    pin(bundle, "scenario", &result.scenario_digest);
    Ok(RunData::McpAuth { result, scenario })
}

/// Checks each recorded document against the raw bytes of the file of the
/// same name under `inputs/evidence/`.
fn check_documents<'a>(
    dir: &AdmittedDir,
    documents: impl Iterator<Item = (&'a str, &'a str)>,
    digest_bytes: fn(&[u8]) -> String,
    bundle: &mut LoadedBundle,
) -> Result<()> {
    let index = dir.index;
    let present = dir.list_files(EVIDENCE_DIR, "evidence inputs")?;
    for (document_id, pinned) in documents {
        if !present.iter().any(|name| name == document_id) {
            return Err(Refusal::MissingInput {
                index,
                input: "evidence document",
            }
            .into());
        }
        let bytes = dir.read_bytes(
            &format!("{EVIDENCE_DIR}/{document_id}"),
            "evidence document",
        )?;
        if digest_bytes(&bytes) != pinned {
            return Err(mismatch(index, "evidence document").into());
        }
        pin(bundle, &format!("document {document_id}"), pinned);
    }
    Ok(())
}

/// Pre-admits every evidence file the scenario names, so the engine's own
/// reader only ever sees files that passed this crate's admission rules.
fn admit_evidence_files(dir: &AdmittedDir, names: &[String]) -> Result<()> {
    let present = dir.list_files(EVIDENCE_DIR, "evidence inputs")?;
    for name in names {
        if !present.iter().any(|p| p == name) {
            return Err(Refusal::MissingInput {
                index: dir.index,
                input: "evidence document",
            }
            .into());
        }
        dir.read_bytes(&format!("{EVIDENCE_DIR}/{name}"), "evidence document")?;
    }
    Ok(())
}

fn bind_supply_chain(
    dir: &AdmittedDir,
    value: &Value,
    bundle: &mut LoadedBundle,
) -> Result<RunData> {
    use dare_supply_chain_security::{
        budget::AdmissionLedger,
        canonical::{digest, digest_bytes},
        corpus::{entry_by_id, scenario_for, CorpusAdapter},
        harness::{StaticAdapter, SupplyChainAdapter},
        local_synthetic::LocalSyntheticAdapter,
        manifest::DareManifest,
        replay::ReplayAdapter,
        simulated::SimulatedAdapter,
        source::SupplyChainMode,
    };
    let index = dir.index;
    let result: SupplyChainSecurityResult = decode(index, "result", value)?;
    let scenario = if dir.has(load::SCENARIO_FILE) {
        load::load_supply_chain(dir, load::SCENARIO_FILE)?
    } else {
        let entry = entry_by_id(&result.scenario_id).ok_or(Refusal::MissingInput {
            index,
            input: "scenario",
        })?;
        scenario_for(&entry)
    };
    same(
        digest(&scenario),
        &result.scenario_digest,
        index,
        "scenario",
    )?;
    pin(bundle, "scenario", &result.scenario_digest);
    let mut ledger = AdmissionLedger::new();
    let rejected = |_| invalid(index, "evidence inputs", "rejected by the engine");
    let evidence = match result.mode {
        SupplyChainMode::Static => {
            check_documents(
                dir,
                result
                    .documents
                    .iter()
                    .map(|d| (d.document_id.as_str(), d.content_digest.as_str())),
                digest_bytes,
                bundle,
            )?;
            admit_evidence_files(dir, &scenario.evidence_files)?;
            StaticAdapter::new(dir.root.join(EVIDENCE_DIR))
                .collect(&scenario, &mut ledger)
                .map_err(rejected)?
        }
        SupplyChainMode::Replay => {
            let (_, capture) = dir.read_json(CAPTURE_FILE, "capture")?;
            let capture: SupplyChainCapture = decode(index, "capture", &capture)?;
            let (_, manifest) = dir.read_json(MANIFEST_FILE, "manifest")?;
            let manifest: DareManifest = decode(index, "manifest", &manifest)?;
            ReplayAdapter::new(capture, manifest)
                .collect(&scenario, &mut ledger)
                .map_err(rejected)?
        }
        SupplyChainMode::Simulated if scenario.reference_behavior.is_some() => {
            SimulatedAdapter::new()
                .collect(&scenario, &mut ledger)
                .map_err(rejected)?
        }
        SupplyChainMode::Simulated => CorpusAdapter
            .collect(&scenario, &mut ledger)
            .map_err(rejected)?,
        SupplyChainMode::LocalSynthetic => LocalSyntheticAdapter::for_scenario(&scenario)
            .collect(&scenario, &mut ledger)
            .map_err(rejected)?,
    };
    same(
        digest(&evidence),
        &result.evidence_digest,
        index,
        "supply-chain evidence",
    )?;
    pin(bundle, "supply-chain evidence", &result.evidence_digest);
    Ok(RunData::SupplyChain { result, evidence })
}

fn bind_a2a(dir: &AdmittedDir, value: &Value, bundle: &mut LoadedBundle) -> Result<RunData> {
    use dare_a2a_security::{
        budget::AdmissionLedger,
        canonical::{digest, digest_bytes},
        capture::ReplayAdapter,
        corpus::{entry_by_id, scenario_for, CorpusAdapter},
        harness::{A2aAdapter, StaticAdapter},
        local_synthetic::LocalSyntheticAdapter,
        policy::A2aPolicy,
        simulated::SimulatedAdapter,
        source::A2aMode,
    };
    let index = dir.index;
    let result: A2aSecurityResult = decode(index, "result", value)?;
    let scenario = if dir.has(load::SCENARIO_FILE) {
        load::load_a2a(dir, load::SCENARIO_FILE)?
    } else {
        let entry = entry_by_id(&result.scenario_id).ok_or(Refusal::MissingInput {
            index,
            input: "scenario",
        })?;
        scenario_for(&entry)
    };
    same(
        digest(&scenario),
        &result.scenario_digest,
        index,
        "scenario",
    )?;
    pin(bundle, "scenario", &result.scenario_digest);
    let mut ledger = AdmissionLedger::new();
    let rejected = |_| invalid(index, "evidence inputs", "rejected by the engine");
    let evidence = match result.mode {
        A2aMode::Static => {
            check_documents(
                dir,
                result
                    .documents
                    .iter()
                    .map(|d| (d.document_id.as_str(), d.content_digest.as_str())),
                digest_bytes,
                bundle,
            )?;
            admit_evidence_files(dir, &scenario.evidence_files)?;
            StaticAdapter::new(dir.root.join(EVIDENCE_DIR))
                .collect(&scenario, &mut ledger)
                .map_err(rejected)?
        }
        A2aMode::Replay => {
            let (_, capture) = dir.read_json(CAPTURE_FILE, "capture")?;
            let capture: A2aCapture = decode(index, "capture", &capture)?;
            let (_, policy) = dir.read_json(POLICY_FILE, "policy")?;
            let policy: A2aPolicy = decode(index, "policy", &policy)?;
            ReplayAdapter::new(capture, policy)
                .collect(&scenario, &mut ledger)
                .map_err(rejected)?
        }
        A2aMode::Simulated if scenario.reference_behavior.is_some() => SimulatedAdapter::new()
            .collect(&scenario, &mut ledger)
            .map_err(rejected)?,
        A2aMode::Simulated => CorpusAdapter
            .collect(&scenario, &mut ledger)
            .map_err(rejected)?,
        A2aMode::LocalSynthetic => LocalSyntheticAdapter::for_scenario(&scenario)
            .collect(&scenario, &mut ledger)
            .map_err(rejected)?,
    };
    same(
        digest(&evidence),
        &result.evidence_digest,
        index,
        "a2a evidence",
    )?;
    pin(bundle, "a2a evidence", &result.evidence_digest);
    Ok(RunData::A2a { result, evidence })
}

fn bind_prompt_injection(value: &Value, bundle: &mut LoadedBundle) -> Result<RunData> {
    let index = bundle.index;
    let result: PromptInjectionResult = decode(index, "result", value)?;
    bundle.evidence.require_all(index, &result.evidence_ids)?;
    // Result-only: the scenario digest is recorded, not re-verified.
    bundle.input_digests.push(result.scenario_digest.clone());
    Ok(RunData::PromptInjection { result })
}

fn bind_multi_turn(dir: &AdmittedDir, value: &Value, bundle: &mut LoadedBundle) -> Result<RunData> {
    let index = dir.index;
    let result: MultiTurnResult = decode(index, "result", value)?;
    let (conversations_bytes, conversations) =
        dir.read_json(CONVERSATIONS_FILE, "conversations")?;
    let runs: Vec<ConversationRun> =
        decode(index, "conversations", &conversations["conversations"])?;
    if runs.len() != result.conversations.len() {
        return Err(mismatch(index, "conversations").into());
    }
    for summary in &result.conversations {
        let run = runs
            .iter()
            .find(|r| r.state.conversation_id == summary.conversation_id)
            .ok_or(mismatch(index, "conversations"))?;
        if run.state.verify_chain().is_err() || run.state.head() != summary.final_chain_digest {
            return Err(mismatch(index, "conversations").into());
        }
    }
    let digest = sha256_prefixed(&conversations_bytes);
    pin(bundle, "conversations", &digest);
    Ok(RunData::MultiTurn {
        result,
        conversations: runs,
    })
}

fn bind_remote(dir: &AdmittedDir, value: &Value, bundle: &mut LoadedBundle) -> Result<RunData> {
    let index = dir.index;
    let schema: Value = serde_json::from_str(REMOTE_RESULT_SCHEMA_JSON)
        .map_err(|_| crate::AttackPathError::Internal("embedded remote result schema"))?;
    let validator = jsonschema::options()
        .build(&schema)
        .map_err(|_| crate::AttackPathError::Internal("embedded remote result schema"))?;
    if validator.iter_errors(value).next().is_some() {
        return Err(invalid(index, "result", "does not match the remote result schema").into());
    }
    bundle.mode = format!("REMOTE_{}", value["protocol"].as_str().unwrap_or("UNKNOWN"));
    bundle.synthetic = false;
    let mut runs = Vec::new();
    for (position, run) in value["runs"].as_array().into_iter().flatten().enumerate() {
        let verdict: dare_security_evidence::Verdict = decode(index, "result", &run["verdict"])?;
        let scenario_digest = run["scenario_digest"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let engine_result = match (run["engine"].as_str(), &run["engine_result"]) {
            (_, Value::Null) => None,
            (Some("PROMPT_INJECTION"), v) => Some(RemoteEngineResult::PromptInjection(decode(
                index, "result", v,
            )?)),
            (Some("MULTI_TURN"), v) => {
                Some(RemoteEngineResult::MultiTurn(decode(index, "result", v)?))
            }
            (Some("A2A"), v) => Some(RemoteEngineResult::A2a(decode(index, "result", v)?)),
            (Some("MCP_AUTH"), v) => Some(RemoteEngineResult::McpAuth(decode(index, "result", v)?)),
            _ => return Err(invalid(index, "result", "names an unknown engine").into()),
        };
        let scenario_file = format!("inputs/run-{position}/scenario.json");
        let mcp_scenario = if run["engine"] == "MCP_AUTH" && dir.has(&scenario_file) {
            let scenario = load::load_mcp_auth(dir, &scenario_file)?;
            same(
                dare_mcp_auth_security::canonical::digest(&scenario),
                &scenario_digest,
                index,
                "remote run scenario",
            )?;
            pin(
                bundle,
                &format!("run {position} scenario"),
                &scenario_digest,
            );
            Some(scenario)
        } else {
            None
        };
        runs.push(RemoteRun {
            position,
            verdict: crate::evidence_index::guard_verdict(verdict),
            scenario_digest,
            engine_result,
            mcp_scenario,
        });
    }
    Ok(RunData::Remote { runs })
}
