//! A2A (Cycle 020) through the engine's STATIC mode (BLUEPRINT AD-11, §6.1–6.2).
//!
//! The A2A replay capture requires `synthetic: true`, so it cannot honestly
//! hold live evidence. STATIC reads real local documents and reports
//! `evidence_is_synthetic() = false`: the capture is projected into those
//! documents (card, trace, peers), the operator's local policy is copied
//! beside them, and the engine decides unchanged.
//!
//! Exchange fields that cannot be observed from outside the target (sender,
//! tenant and principal claims, the scheme used, delegation, idempotency,
//! metadata) are left empty; the engine treats missing evidence as
//! INCONCLUSIVE, never PASS.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use dare_a2a_security::agent_card::{
    AgentCard, CardExtension, CardInterface, CardSignatureEvidence, CardSkill,
    DeclaredSecurityScheme,
};
use dare_a2a_security::budget::AdmissionLedger;
use dare_a2a_security::corpus::{entry_by_id, scenario_for};
use dare_a2a_security::evidence_bridge::build_evidence;
use dare_a2a_security::harness::StaticAdapter;
use dare_a2a_security::message::{Exchange, MessagePart};
use dare_a2a_security::model::A2aScenario;
use dare_a2a_security::peer::PeerIdentity;
use dare_a2a_security::result::run_scenario;
use dare_a2a_security::source::{
    A2aMode, EvidenceSource, MessageRole, OperationEffect, SecuritySchemeKind, TransportKind,
    VerificationStatus,
};
use serde_json::Value;

use crate::canonical::short_hex;
use crate::capture::{Capture, ScenarioRef};
use crate::engines::{entries_for, evidence_time, final_verdict, first_transport, EngineOutcome};
use crate::error::{RemoteError, Result};
use crate::gateway::EgressGateway;
use crate::outcome::{StopReason, TransportOutcome};
use crate::plan::EngineKind;
use crate::protocol::{a2a, Method};

pub const CARD_FILE: &str = "remote-card.json";
pub const TRACE_FILE: &str = "remote-trace.json";
pub const PEERS_FILE: &str = "remote-peers.json";
pub const POLICY_FILE: &str = "remote-policy.json";

/// The exchange fields a live run cannot observe.
pub const NOT_OBSERVABLE: [&str; 7] = [
    "sender_claim",
    "tenant_claim",
    "initiating_principal",
    "security_scheme_used",
    "delegation_chain_id",
    "idempotency_key",
    "metadata",
];

/// The JSON-RPC id of the single probe and of its task status request.
pub const PROBE_ID: u64 = 1;
pub const TASK_ID_REQUEST: u64 = 2;

#[derive(Debug, Clone)]
pub struct Loaded {
    pub scenario: A2aScenario,
    pub digest: String,
}

fn engine(error: impl std::fmt::Display) -> RemoteError {
    RemoteError::Engine(format!("a2a: {error}"))
}

/// Load an A2A-LAB entry by id; its digest is what an authorization grants.
pub fn load(id: &str) -> Result<Loaded> {
    let entry = entry_by_id(id).ok_or(RemoteError::Refused("the A2A corpus has no such entry"))?;
    let scenario = scenario_for(&entry);
    let digest = dare_a2a_security::canonical::digest(&scenario).map_err(engine)?;
    Ok(Loaded { scenario, digest })
}

fn sref(loaded: &Loaded, step: u32) -> ScenarioRef {
    ScenarioRef {
        engine: EngineKind::A2a,
        scenario_id: loaded.scenario.scenario_id.clone(),
        conversation_id: Some(context_id(loaded)),
        node_id: None,
        step: Some(step),
    }
}

fn context_id(loaded: &Loaded) -> String {
    format!("ctx-{}", loaded.scenario.scenario_id.to_ascii_lowercase())
}

/// Live: the card, one probe whose text is the scenario's approved
/// description, and the probe's task status when the agent returned a task.
pub async fn live(
    gateway: &mut EgressGateway,
    loaded: &Loaded,
    methods: &BTreeSet<Method>,
) -> Result<()> {
    let (_, card) = a2a::fetch_card(gateway, sref(loaded, 0)).await?;
    let version = card
        .as_ref()
        .map(a2a::declared_version)
        .unwrap_or_else(|_| "1.0.0".to_owned());
    if !methods.contains(&Method::A2aMessageSend) {
        return Ok(());
    }
    let (_, reply) = a2a::send_message(
        gateway,
        &version,
        PROBE_ID,
        &format!("{}-probe", context_id(loaded)),
        &context_id(loaded),
        &loaded.scenario.description,
        sref(loaded, 1),
    )
    .await?;
    if let (Ok(reply), true) = (reply, methods.contains(&Method::A2aTasksGet)) {
        if let Some(task) = reply.task_id {
            // The status is captured; the verdict pass reads it from the capture.
            let _status =
                a2a::get_task(gateway, &version, TASK_ID_REQUEST, &task, sref(loaded, 2)).await?;
        }
    }
    Ok(())
}

fn peer_id(origin: &str) -> String {
    format!("peer-{}", short_hex(origin.as_bytes(), 16))
}

fn transport(value: &str) -> std::result::Result<TransportKind, TransportOutcome> {
    match value {
        "JSONRPC" => Ok(TransportKind::JsonRpc),
        "GRPC" => Ok(TransportKind::Grpc),
        "HTTP+JSON" => Ok(TransportKind::HttpJson),
        _ => Err(TransportOutcome::ProtocolViolation),
    }
}

fn truncate(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

fn scheme(id: &str, v: &Value) -> std::result::Result<DeclaredSecurityScheme, TransportOutcome> {
    let kind = match v.get("type").and_then(Value::as_str) {
        Some("apiKey") => SecuritySchemeKind::ApiKey,
        Some("http") => match v
            .get("scheme")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("bearer") => SecuritySchemeKind::HttpBearer,
            Some("basic") => SecuritySchemeKind::HttpBasic,
            _ => return Err(TransportOutcome::ProtocolViolation),
        },
        Some("oauth2") => {
            let flows = v.get("flows");
            if flows.and_then(|f| f.get("clientCredentials")).is_some() {
                SecuritySchemeKind::OAuth2ClientCredentials
            } else if flows.and_then(|f| f.get("authorizationCode")).is_some() {
                SecuritySchemeKind::OAuth2AuthorizationCode
            } else {
                return Err(TransportOutcome::ProtocolViolation);
            }
        }
        Some("openIdConnect") => SecuritySchemeKind::OpenIdConnect,
        Some("mutualTLS") => SecuritySchemeKind::MutualTls,
        _ => return Err(TransportOutcome::ProtocolViolation),
    };
    let flow = v
        .get("flows")
        .and_then(Value::as_object)
        .and_then(|f| f.values().next());
    Ok(DeclaredSecurityScheme {
        scheme_id: truncate(id, 128),
        kind,
        issuer: v
            .get("openIdConnectUrl")
            .and_then(Value::as_str)
            .map(str::to_owned),
        token_endpoint: flow
            .and_then(|f| f.get("tokenUrl"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        scopes: flow
            .and_then(|f| f.get("scopes"))
            .and_then(Value::as_object)
            .map(|s| s.keys().cloned().collect())
            .unwrap_or_default(),
    })
}

/// Project a real Agent Card (1.0 or 0.3-era shape) into the engine's model.
pub fn project_card(
    card: &Value,
    origin: &str,
) -> std::result::Result<AgentCard, TransportOutcome> {
    let name = card
        .get("name")
        .and_then(Value::as_str)
        .ok_or(TransportOutcome::ProtocolViolation)?;
    if name.chars().count() > 200 {
        return Err(TransportOutcome::ProtocolViolation);
    }
    let version = a2a::declared_version(card);
    let mut interfaces = Vec::new();
    if let Some(list) = card.get("supportedInterfaces").and_then(Value::as_array) {
        for i in list.iter().take(8) {
            interfaces.push(CardInterface {
                url: i
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                transport: transport(
                    i.get("protocolBinding")
                        .or_else(|| i.get("transport"))
                        .and_then(Value::as_str)
                        .unwrap_or("JSONRPC"),
                )?,
                protocol_version: i
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or(&version)
                    .to_owned(),
            });
        }
    } else if let Some(url) = card.get("url").and_then(Value::as_str) {
        interfaces.push(CardInterface {
            url: url.to_owned(),
            transport: transport(
                card.get("preferredTransport")
                    .and_then(Value::as_str)
                    .unwrap_or("JSONRPC"),
            )?,
            protocol_version: version.clone(),
        });
        for i in card
            .get("additionalInterfaces")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(7)
        {
            interfaces.push(CardInterface {
                url: i
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                transport: transport(
                    i.get("transport")
                        .and_then(Value::as_str)
                        .unwrap_or("JSONRPC"),
                )?,
                protocol_version: version.clone(),
            });
        }
    }
    let security_schemes = card
        .get("securitySchemes")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .take(16)
                .map(|(k, v)| scheme(k, v))
                .collect::<std::result::Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let skills = card
        .get("skills")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .take(64)
                .filter_map(|s| {
                    Some(CardSkill {
                        skill_id: truncate(s.get("id")?.as_str()?, 128),
                        name: s
                            .get("name")
                            .and_then(Value::as_str)
                            .map(|n| truncate(n, 200)),
                        security_requirements: s
                            .get("security")
                            .and_then(Value::as_array)
                            .map(|reqs| {
                                reqs.iter()
                                    .filter_map(Value::as_object)
                                    .flat_map(|o| o.keys().cloned())
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let capabilities = card.get("capabilities");
    let extensions = capabilities
        .and_then(|c| c.get("extensions"))
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .take(32)
                .filter_map(|e| {
                    Some(CardExtension {
                        extension_id: truncate(e.get("uri")?.as_str()?, 256),
                        required: e.get("required").and_then(Value::as_bool).unwrap_or(false),
                        claims_authority: false,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let signature = card
        .get("signatures")
        .and_then(Value::as_array)
        .filter(|s| !s.is_empty())
        .map(|s| CardSignatureEvidence {
            // v1 verifies no signature, so a signature can never read as valid.
            status: VerificationStatus::Indeterminate,
            signer_key_id: s[0]
                .get("header")
                .and_then(|h| h.get("kid"))
                .and_then(Value::as_str)
                .map(|k| truncate(k, 128)),
            key_location: None,
            recorded_by: EvidenceSource::AgentCard,
        });
    Ok(AgentCard {
        // The engine binds a card to its peer by `card_id == peer_id`
        // (`normalize.rs`), so the card carries the peer's id.
        card_id: peer_id(origin),
        name: truncate(name.trim(), 200),
        description: card
            .get("description")
            .and_then(Value::as_str)
            .map(|d| truncate(d, 1024)),
        provider: card
            .get("provider")
            .and_then(|p| p.get("organization"))
            .and_then(Value::as_str)
            .map(|p| truncate(p.trim(), 200)),
        interfaces,
        security_schemes,
        skills,
        extensions,
        signature,
        declares_push_notifications: capabilities
            .and_then(|c| c.get("pushNotifications"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        metadata: BTreeMap::new(),
        evidence_source: EvidenceSource::AgentCard,
    })
}

/// Project one reply into an exchange.
pub fn project_exchange(
    reply: &a2a::A2aReply,
    message_id: &str,
    origin: &str,
    endpoint: &str,
    version: &str,
) -> Exchange {
    Exchange {
        message_id: message_id.to_owned(),
        peer_id: peer_id(origin),
        role: MessageRole::RemotePeer,
        sender_claim: None,
        task_id: reply.task_id.clone(),
        context_id: reply.context_id.clone(),
        tenant_claim: None,
        initiating_principal: None,
        requested_skill: None,
        protocol_version: version.to_owned(),
        transport: TransportKind::JsonRpc,
        interface_url: Some(format!("{origin}{endpoint}")),
        security_scheme_used: None,
        delegation_chain_id: None,
        operation_effect: OperationEffect::ReadOnly,
        idempotency_key: None,
        is_repeat: false,
        parts: reply
            .parts
            .iter()
            .enumerate()
            .map(|(i, p)| MessagePart {
                part_id: format!("p{i}"),
                kind: truncate(&p.kind, 32),
                bytes: p.bytes,
                treated_as_instruction: false,
                data_labels: BTreeSet::new(),
            })
            .collect(),
        extensions_used: BTreeSet::new(),
        push_config_id: None,
        metadata: BTreeMap::new(),
        evidence_source: EvidenceSource::CapturedTrace,
    }
}

/// Decide from the capture alone. `endpoint` is the authorization's A2A path.
pub fn verdict(
    capture: &Capture,
    loaded: &Loaded,
    endpoint: &str,
    policy: &Path,
    work: &Path,
    unfinished: Option<StopReason>,
) -> Result<EngineOutcome> {
    let id = loaded.scenario.scenario_id.as_str();
    let origin = capture.origin.as_str();
    let entries: Vec<_> = entries_for(capture, EngineKind::A2a, id).collect();
    let mut files = Vec::new();
    let mut projection_failure = None;
    let _ = fs::remove_dir_all(work);
    fs::create_dir_all(work)?;

    let card = entries
        .iter()
        .find(|e| e.method == Method::A2aAgentCardGet)
        .and_then(|e| {
            e.transport_error
                .is_none()
                .then(|| a2a::parse_card(e.response_body.as_deref()))
                .and_then(std::result::Result::ok)
        });
    let version = card
        .as_ref()
        .map(a2a::declared_version)
        .unwrap_or_else(|| "1.0.0".to_owned());
    let logical = card
        .as_ref()
        .and_then(|c| c.get("name"))
        .and_then(Value::as_str)
        .map(|n| truncate(n.trim(), 200));
    if let Some(card) = &card {
        match project_card(card, origin) {
            Ok(projected) => {
                fs::write(
                    work.join(CARD_FILE),
                    serde_json::to_vec(&projected)
                        .map_err(|_| RemoteError::Serialization("card"))?,
                )?;
                files.push(CARD_FILE.to_owned());
            }
            Err(outcome) => projection_failure = Some(outcome),
        }
    }
    let exchanges: Vec<Exchange> = entries
        .iter()
        .filter(|e| e.method == Method::A2aMessageSend && e.transport_error.is_none())
        .filter_map(|e| a2a::parse_reply(e.response_body.as_deref(), PROBE_ID).ok())
        .map(|reply| {
            project_exchange(
                &reply,
                &format!("{}-probe", context_id(loaded)),
                origin,
                endpoint,
                &version,
            )
        })
        .collect();
    if !exchanges.is_empty() {
        fs::write(
            work.join(TRACE_FILE),
            serde_json::to_vec(&exchanges).map_err(|_| RemoteError::Serialization("trace"))?,
        )?;
        files.push(TRACE_FILE.to_owned());
        let peer = PeerIdentity {
            peer_id: peer_id(origin),
            logical_agent_id: logical.unwrap_or_else(|| peer_id(origin)),
            card_provider: card
                .as_ref()
                .and_then(|c| c.get("provider"))
                .and_then(|p| p.get("organization"))
                .and_then(Value::as_str)
                .map(|p| truncate(p.trim(), 200)),
            // An identity, not a location: the engine refuses URL-shaped
            // identities, so the scheme is dropped (`host[:port]`).
            endpoint_identity: Some(origin.trim_start_matches("https://").to_owned()),
            authenticated_principal: None,
            delegated_subject: None,
            tenant: None,
            audience: None,
            evidence_source: EvidenceSource::CapturedTrace,
        };
        fs::write(
            work.join(PEERS_FILE),
            serde_json::to_vec(&vec![peer]).map_err(|_| RemoteError::Serialization("peers"))?,
        )?;
        files.push(PEERS_FILE.to_owned());
    }
    fs::copy(policy, work.join(POLICY_FILE))
        .map_err(|_| RemoteError::Refused("the local A2A policy file could not be read"))?;
    files.push(POLICY_FILE.to_owned());

    let mut derived = loaded.scenario.clone();
    derived.mode = A2aMode::Static;
    derived.evidence_files = files;
    let mut ledger = AdmissionLedger::new();
    let result = run_scenario(&derived, &StaticAdapter::new(work), &mut ledger).map_err(engine)?;
    let evidence = build_evidence(&derived, &result, evidence_time(capture)).map_err(engine)?;
    let _ = fs::remove_dir_all(work);

    let transport = first_transport(capture, EngineKind::A2a, id).or(projection_failure);
    let engine_verdict = result.verdict;
    Ok(EngineOutcome {
        engine: EngineKind::A2a,
        scenario_id: id.to_owned(),
        engine_verdict,
        verdict: final_verdict(engine_verdict, transport, unfinished),
        transport,
        unfinished,
        self_reported_fields: BTreeSet::new(),
        not_observable: NOT_OBSERVABLE.to_vec(),
        result: serde_json::to_value(&result)
            .map_err(|_| RemoteError::Serialization("a2a result"))?,
        evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ORIGIN: &str = "https://127.0.0.1:18443";

    #[test]
    fn a_0_3_card_projects_every_blueprint_row() {
        let card = json!({
            "name": "planner", "description": "d", "protocolVersion": "0.3.0",
            "provider": {"organization": "Acme"},
            "url": "https://127.0.0.1:18443/a2a/v1", "preferredTransport": "JSONRPC",
            "additionalInterfaces": [{"url": "https://127.0.0.1:18443/grpc", "transport": "GRPC"}],
            "securitySchemes": {
                "k": {"type": "apiKey"}, "b": {"type": "http", "scheme": "Bearer"}, "basic": {"type": "http", "scheme": "basic"},
                "cc": {"type": "oauth2", "flows": {"clientCredentials": {"tokenUrl": "https://127.0.0.1/t", "scopes": {"read": ""}}}},
                "ac": {"type": "oauth2", "flows": {"authorizationCode": {"tokenUrl": "https://127.0.0.1/t", "scopes": {}}}},
                "oidc": {"type": "openIdConnect", "openIdConnectUrl": "https://127.0.0.1/.well-known/openid-configuration"},
                "mtls": {"type": "mutualTLS"}
            },
            "skills": [{"id": "summarize", "name": "Summarize", "security": [{"cc": ["read"]}]}],
            "capabilities": {"pushNotifications": true, "extensions": [{"uri": "urn:x", "required": true}]},
            "signatures": [{"protected": "e30", "header": {"kid": "k1"}}]
        });
        let p = project_card(&card, ORIGIN).unwrap();
        assert_eq!(p.card_id, peer_id(ORIGIN), "bound to its peer");
        assert_eq!(p.provider.as_deref(), Some("Acme"));
        assert_eq!(p.interfaces.len(), 2);
        assert_eq!(p.interfaces[1].transport, TransportKind::Grpc);
        let kinds: BTreeSet<_> = p.security_schemes.iter().map(|s| s.kind.as_str()).collect();
        assert_eq!(kinds.len(), 7);
        let cc = p
            .security_schemes
            .iter()
            .find(|s| s.scheme_id == "cc")
            .unwrap();
        assert_eq!(cc.token_endpoint.as_deref(), Some("https://127.0.0.1/t"));
        assert!(cc.scopes.contains("read"));
        assert!(p.skills[0].security_requirements.contains("cc"));
        assert!(p.extensions[0].required && !p.extensions[0].claims_authority);
        assert_eq!(
            p.signature.as_ref().unwrap().status,
            VerificationStatus::Indeterminate
        );
        assert_eq!(
            p.signature.as_ref().unwrap().signer_key_id.as_deref(),
            Some("k1")
        );
        assert!(p.declares_push_notifications);
        p.validate().expect("the engine accepts the projection");
    }

    #[test]
    fn a_1_0_card_with_supported_interfaces_projects() {
        let card = json!({"name": "a", "supportedInterfaces": [{"url": "https://127.0.0.1/a2a", "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0.0"}]});
        let p = project_card(&card, ORIGIN).unwrap();
        assert_eq!(p.interfaces[0].transport, TransportKind::HttpJson);
        assert_eq!(p.interfaces[0].protocol_version, "1.0.0");
        p.validate().unwrap();
    }

    #[test]
    fn unknown_transports_and_schemes_are_protocol_violations() {
        assert_eq!(
            project_card(
                &json!({"name": "a", "url": "https://x", "preferredTransport": "SOAP"}),
                ORIGIN
            )
            .err(),
            Some(TransportOutcome::ProtocolViolation)
        );
        assert_eq!(
            project_card(
                &json!({"name": "a", "securitySchemes": {"x": {"type": "magic"}}}),
                ORIGIN
            )
            .err(),
            Some(TransportOutcome::ProtocolViolation)
        );
        assert_eq!(
            project_card(&json!({"description": "no name"}), ORIGIN).err(),
            Some(TransportOutcome::ProtocolViolation)
        );
    }

    #[test]
    fn exchanges_leave_non_observable_fields_empty() {
        let reply = a2a::A2aReply {
            task_id: Some("t".into()),
            context_id: Some("c".into()),
            state: None,
            parts: vec![a2a::ReplyPart {
                kind: "text".into(),
                bytes: 2,
                text: Some("ok".into()),
            }],
            error_code: None,
        };
        let e = project_exchange(&reply, "m1", ORIGIN, "/a2a/v1", "1.0.0");
        assert_eq!(
            e.interface_url.as_deref(),
            Some("https://127.0.0.1:18443/a2a/v1")
        );
        assert!(
            e.sender_claim.is_none()
                && e.tenant_claim.is_none()
                && e.initiating_principal.is_none()
        );
        assert!(
            e.security_scheme_used.is_none()
                && e.delegation_chain_id.is_none()
                && e.idempotency_key.is_none()
                && e.metadata.is_empty()
        );
        assert_eq!(e.operation_effect, OperationEffect::ReadOnly);
        assert!(!e.parts[0].treated_as_instruction);
        e.validate().expect("the engine accepts the projection");
    }
}
