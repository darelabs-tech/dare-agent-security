//! Shared Cycle 001 record assembly for discovery evidence.

use std::collections::BTreeMap;

use dare_security_evidence::{
    AuthorizationContext, Decision, EvidenceTimestamps, ExpectedOutcome, HashRef,
    NormalizedOperation, ObservationSource, ObservedOutcome, Precondition, SchemaRef,
    SecurityEvidence, SeverityAssessment, SeverityLevel, StandardMapping, TargetRef, VectorRef,
    Verdict,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;

use super::error::EvidenceBridgeError;
use super::observation::DiscoveryObservation;
use crate::inventory::{DiscoveryInventory, DiscoveryTarget};
use crate::policy::PolicyProfile;
use crate::sanitize::{redact_text, sanitize_error_display, sanitize_inventory_target};

/// Canonical schema identity URI required by evidence v1.
pub(super) const EVIDENCE_SCHEMA_ID: &str = "https://darelabs.tech/schemas/evidence";

/// Namespaced extension key for MCP discovery details.
pub const EXTENSION_KEY: &str = "dare.mcp.discovery";

/// Stable vector version for the initial Cycle 002 family.
pub const VECTOR_VERSION: &str = "1.0.0";

pub(super) struct RecordPlan {
    pub vector_id: &'static str,
    pub vector_name: &'static str,
    pub vector_code: &'static str,
    pub expected: ExpectedOutcome,
    pub observed: ObservedOutcome,
    pub verdict: Verdict,
    pub extension: Value,
    pub severity: Option<SeverityAssessment>,
}

pub(super) fn timestamps_are_ordered(observation: &DiscoveryObservation) -> bool {
    observation.started_at <= observation.observed_at
        && observation.observed_at <= observation.recorded_at
}

pub(super) fn safe_text(input: &str) -> String {
    redact_text(input)
}

pub(super) fn safe_error(raw: &str) -> String {
    sanitize_error_display(&raw)
}

pub(super) fn sanitized_target(target: &DiscoveryTarget) -> DiscoveryTarget {
    let mut cloned = target.clone();
    sanitize_inventory_target(&mut cloned);
    cloned
}

pub(super) fn run_revision(observation: &DiscoveryObservation) -> String {
    match &observation.inventory {
        Some(inventory) => {
            let generated = inventory
                .generated_at
                .format(&Rfc3339)
                .unwrap_or_else(|_| "unknown-time".to_owned());
            match &inventory.scanner {
                Some(scanner) => format!(
                    "{}@{}#{}",
                    safe_text(&scanner.name),
                    safe_text(&scanner.version),
                    generated
                ),
                None => format!("unscanned#{generated}"),
            }
        }
        None => "unscanned".to_owned(),
    }
}

pub(super) fn inventory_revision(inventory: Option<&DiscoveryInventory>) -> String {
    match inventory {
        Some(inventory) => inventory.schema.version.to_string(),
        None => "unknown".to_owned(),
    }
}

pub(super) fn profile_token(profile: PolicyProfile) -> &'static str {
    match profile {
        PolicyProfile::Current2026_07_28 => "current-2026-07-28",
        PolicyProfile::Legacy2024_11_05 => "legacy-2024-11-05",
    }
}

pub(super) fn build_extension(
    observation: &DiscoveryObservation,
    vector_code: &str,
    extra: BTreeMap<String, Value>,
) -> Value {
    let target = sanitized_target(&observation.target);
    let mut body = serde_json::Map::new();
    body.insert(
        "inventory_revision".to_owned(),
        json!(inventory_revision(observation.inventory.as_ref())),
    );
    body.insert("run_revision".to_owned(), json!(run_revision(observation)));
    body.insert("vector_code".to_owned(), json!(vector_code));
    body.insert(
        "policy_profile".to_owned(),
        json!(profile_token(observation.policy_profile)),
    );
    body.insert("target_id".to_owned(), json!(safe_text(&target.id)));
    if let Some(inventory) = &observation.inventory {
        body.insert(
            "protocol_revision".to_owned(),
            json!(safe_text(&inventory.protocol.revision)),
        );
        body.insert(
            "protocol_negotiated".to_owned(),
            json!(inventory.protocol.negotiated),
        );
        body.insert(
            "completeness".to_owned(),
            json!(match inventory.completeness {
                crate::inventory::Completeness::Complete => "COMPLETE",
                crate::inventory::Completeness::Partial => "PARTIAL",
            }),
        );
        body.insert(
            "redaction_applied".to_owned(),
            json!(inventory.redaction.applied),
        );
        body.insert(
            "redaction_strategy".to_owned(),
            json!(match inventory.redaction.strategy {
                crate::inventory::RedactionStrategy::None => "NONE",
                crate::inventory::RedactionStrategy::Partial => "PARTIAL",
                crate::inventory::RedactionStrategy::Full => "FULL",
            }),
        );
    }
    body.insert(
        "invoked_method_count".to_owned(),
        json!(observation.invoked_methods.len() as u64),
    );
    let methods: Vec<Value> = observation
        .invoked_methods
        .iter()
        .map(|method| json!(safe_text(method)))
        .collect();
    body.insert("invoked_methods".to_owned(), Value::Array(methods));
    for (key, value) in extra {
        body.insert(key, value);
    }
    Value::Object(body)
}

pub(super) fn assemble(
    observation: &DiscoveryObservation,
    plan: RecordPlan,
) -> Result<SecurityEvidence, EvidenceBridgeError> {
    if !timestamps_are_ordered(observation) {
        return Err(EvidenceBridgeError::InvalidTimestamps);
    }

    let target = sanitized_target(&observation.target);
    let target_id = safe_text(&target.id);
    let run = run_revision(observation);
    let record_id = deterministic_urn(plan.vector_id, &target_id, &run);
    let hash = observation_hash(plan.vector_id, &target_id, &run, &plan.extension);

    let mut extensions = BTreeMap::new();
    extensions.insert(EXTENSION_KEY.to_owned(), plan.extension);

    let redaction_fields = redacted_target_fields(&observation.target, &target);
    let (redaction_applied, redaction_strategy, redaction_field_list) =
        if redaction_fields.is_empty() {
            (
                false,
                dare_security_evidence::RedactionStrategy::NoneRequired,
                Vec::new(),
            )
        } else {
            (
                true,
                dare_security_evidence::RedactionStrategy::Mask,
                redaction_fields,
            )
        };

    let evidence = SecurityEvidence {
        schema: SchemaRef {
            id: EVIDENCE_SCHEMA_ID.to_owned(),
            version: dare_security_evidence::SchemaVersion::V1,
        },
        id: record_id,
        vector: VectorRef {
            id: plan.vector_id.to_owned(),
            version: VECTOR_VERSION.to_owned(),
            name: Some(plan.vector_name.to_owned()),
        },
        target: TargetRef {
            type_: "service".to_owned(),
            id: target_id.clone(),
            name: target.display_name.as_ref().map(|name| safe_text(name)),
            software: observation
                .inventory
                .as_ref()
                .and_then(|inv| inv.server.as_ref())
                .map(|server| safe_text(&server.name)),
            software_version: observation
                .inventory
                .as_ref()
                .and_then(|inv| inv.server.as_ref())
                .and_then(|server| server.version.as_ref())
                .map(|version| safe_text(version)),
            protocol: None,
            protocol_version: None,
        },
        preconditions: vec![
            Precondition {
                id: Some("passive-discovery".to_owned()),
                description: "scan is passive list-only discovery".to_owned(),
                satisfied: true,
            },
            Precondition {
                id: Some("operator-target".to_owned()),
                description: "target identity was operator-supplied".to_owned(),
                satisfied: true,
            },
        ],
        operation: Some(NormalizedOperation {
            kind: "discovery.baseline".to_owned(),
            name: plan.vector_code.to_owned(),
            resource: Some(target_id),
            arguments_digest: Some(hash.clone()),
            attributes: None,
        }),
        authorization_context: Some(AuthorizationContext {
            principal_id: None,
            agent_id: Some(scanner_agent(observation)),
            authn_method: None,
            policy_id: Some(profile_token(observation.policy_profile).to_owned()),
            policy_version: Some("1.0.0".to_owned()),
            context_attributes: None,
        }),
        expected: plan.expected,
        observed: plan.observed,
        verdict: plan.verdict,
        severity: plan.severity,
        standards: vec![StandardMapping {
            organization: "DARE Labs".to_owned(),
            standard: "MCP Discovery Baseline".to_owned(),
            version: Some("1".to_owned()),
            control: plan.vector_id.to_owned(),
            url: None,
        }],
        artifacts: Vec::new(),
        hashes: vec![hash],
        redaction: dare_security_evidence::RedactionMetadata {
            applied: redaction_applied,
            strategy: redaction_strategy,
            fields: redaction_field_list,
        },
        timestamps: EvidenceTimestamps {
            started_at: Some(observation.started_at),
            observed_at: observation.observed_at,
            recorded_at: observation.recorded_at,
        },
        extensions: Some(extensions),
    };

    validate_built(&evidence)?;
    Ok(evidence)
}

pub(super) fn fail_severity(rationale: &str) -> SeverityAssessment {
    SeverityAssessment {
        level: SeverityLevel::Medium,
        rationale: safe_text(rationale),
    }
}

pub(super) fn expected_allow(result: &str, description: &str) -> ExpectedOutcome {
    ExpectedOutcome {
        decision: Some(Decision::Allow),
        result: Some(result.to_owned()),
        description: Some(description.to_owned()),
    }
}

pub(super) fn observed_decision(
    decision: Decision,
    result: &str,
    description: &str,
    source: ObservationSource,
) -> ObservedOutcome {
    ObservedOutcome {
        decision: Some(decision),
        result: Some(result.to_owned()),
        description: Some(safe_text(description)),
        source,
    }
}

pub(super) fn inconclusive_outcomes(
    expected_description: &str,
    observed_description: &str,
    source: ObservationSource,
) -> (ExpectedOutcome, ObservedOutcome) {
    (
        ExpectedOutcome {
            decision: None,
            result: None,
            description: Some(expected_description.to_owned()),
        },
        ObservedOutcome {
            decision: None,
            result: None,
            description: Some(safe_text(observed_description)),
            source,
        },
    )
}

pub(super) fn error_outcomes(
    expected_description: &str,
    observed_description: &str,
    source: ObservationSource,
) -> (ExpectedOutcome, ObservedOutcome) {
    (
        ExpectedOutcome {
            decision: None,
            result: None,
            description: Some(expected_description.to_owned()),
        },
        ObservedOutcome {
            decision: None,
            result: None,
            description: Some(safe_text(observed_description)),
            source,
        },
    )
}

fn scanner_agent(observation: &DiscoveryObservation) -> String {
    observation
        .inventory
        .as_ref()
        .and_then(|inventory| inventory.scanner.as_ref())
        .map(|scanner| safe_text(&scanner.name))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "dare-agent-security".to_owned())
}

fn redacted_target_fields(original: &DiscoveryTarget, sanitized: &DiscoveryTarget) -> Vec<String> {
    let mut fields = Vec::new();
    if original.id != sanitized.id {
        fields.push("target.id".to_owned());
    }
    if original.display_name != sanitized.display_name {
        fields.push("target.name".to_owned());
    }
    if original.endpoint_fingerprint != sanitized.endpoint_fingerprint {
        fields.push("target.endpoint_fingerprint".to_owned());
    }
    fields
}

fn deterministic_urn(vector_id: &str, target_id: &str, run_revision: &str) -> String {
    let digest = sha256_bytes(&[
        vector_id.as_bytes(),
        b"|",
        target_id.as_bytes(),
        b"|",
        run_revision.as_bytes(),
    ]);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "urn:uuid:{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn observation_hash(
    vector_id: &str,
    target_id: &str,
    run_revision: &str,
    extension: &Value,
) -> HashRef {
    let canonical = serde_json::to_vec(&json!({
        "vector": vector_id,
        "target": target_id,
        "run": run_revision,
        "extension": extension,
    }))
    .unwrap_or_else(|_| b"{}".to_vec());
    HashRef {
        algorithm: "sha256".to_owned(),
        value: hex_lower(&sha256_bytes(&[canonical.as_slice()])),
    }
}

fn sha256_bytes(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn validate_built(evidence: &SecurityEvidence) -> Result<(), EvidenceBridgeError> {
    dare_security_evidence::validate(evidence)
        .map_err(|err| EvidenceBridgeError::from_evidence(&err))?;
    let instance =
        serde_json::to_value(evidence).map_err(|_| EvidenceBridgeError::Serialization)?;
    dare_security_evidence::validate_instance(&instance)
        .map_err(|err| EvidenceBridgeError::from_evidence(&err))?;
    Ok(())
}
