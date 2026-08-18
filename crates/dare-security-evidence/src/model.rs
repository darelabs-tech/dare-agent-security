//! Canonical public evidence types.
//!
//! Field names are protocol-neutral. Protocol-specific data may only appear
//! inside the optional `extensions` map, never as required core fields.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::redaction::RedactionMetadata;
use crate::verdict::Verdict;
use crate::version::SchemaVersion;

/// Top-level canonical security evidence record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEvidence {
    /// Schema identifier and version for this record.
    pub schema: SchemaRef,
    /// Stable evidence record identifier (string in the public contract).
    pub id: String,
    /// Vector that produced this evidence.
    pub vector: VectorRef,
    /// Operator-safe target identifier.
    pub target: TargetRef,
    /// Conditions required to interpret the vector.
    pub preconditions: Vec<Precondition>,
    /// Protocol-neutral operation representation, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<NormalizedOperation>,
    /// Authorization metadata (never raw credentials).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_context: Option<AuthorizationContext>,
    /// Expected deterministic outcome.
    pub expected: ExpectedOutcome,
    /// Observed outcome.
    pub observed: ObservedOutcome,
    /// Verdict. Required; there is no implicit default.
    pub verdict: Verdict,
    /// Optional severity. Must not be inferred solely from the verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<SeverityAssessment>,
    /// Standards attribution mappings (not endorsements).
    #[serde(default)]
    pub standards: Vec<StandardMapping>,
    /// References to supporting artifacts (metadata only).
    #[serde(default)]
    pub artifacts: Vec<EvidenceArtifactRef>,
    /// Hash metadata (algorithm + digest), not signatures.
    #[serde(default)]
    pub hashes: Vec<HashRef>,
    /// Mandatory redaction declaration.
    pub redaction: RedactionMetadata,
    /// RFC 3339 timestamps.
    pub timestamps: EvidenceTimestamps,
    /// Deliberate namespaced extension container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<BTreeMap<String, Value>>,
}

/// Schema identity for an evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaRef {
    /// Canonical schema identifier URI.
    pub id: String,
    /// Schema version (`MAJOR.MINOR.PATCH`).
    pub version: SchemaVersion,
}

/// Reference to the executed security/conformance vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorRef {
    /// Vector identifier.
    pub id: String,
    /// Vector version string.
    pub version: String,
    /// Optional human-readable name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Operator-safe target of a vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRef {
    /// Target class (generic, not a protocol-specific enum).
    #[serde(rename = "type")]
    pub type_: String,
    /// Operator-safe identifier. Must not embed secrets.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
}

/// Condition required to interpret the vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Precondition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub description: String,
    pub satisfied: bool,
}

/// Protocol-neutral operation representation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedOperation {
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments_digest: Option<HashRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<BTreeMap<String, Value>>,
}

/// Authorization metadata. Identifiers only — never credentials.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authn_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_attributes: Option<BTreeMap<String, Value>>,
}

/// Generic expected outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Generic observed outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub source: ObservationSource,
}

/// Common authorization decision vocabulary.
///
/// Namespaced protocol extensions belong in `SecurityEvidence.extensions`,
/// not as extra core enum members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Deny,
    ReEvaluate,
    RequiresApproval,
    NotApplicable,
}

/// Where an observation was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationSource {
    ProtocolResponse,
    PolicyEngine,
    RuntimeEvent,
    Fixture,
}

/// Optional severity assessment. Independent from verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeverityAssessment {
    pub level: SeverityLevel,
    pub rationale: String,
}

/// Initial severity vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SeverityLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Attribution to an upstream standard or control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandardMapping {
    pub organization: String,
    pub standard: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub control: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Metadata reference to a supporting artifact. Blobs are not inlined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifactRef {
    #[serde(rename = "type")]
    pub type_: String,
    pub uri_or_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<HashRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub redacted: bool,
}

/// Hash algorithm + digest metadata (no signatures).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashRef {
    pub algorithm: String,
    pub value: String,
}

/// RFC 3339 UTC timestamps for evidence lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceTimestamps {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub started_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub recorded_at: OffsetDateTime,
}

#[cfg(test)]
pub(crate) fn sample_hash() -> HashRef {
    HashRef {
        algorithm: "sha256".to_owned(),
        value: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
    }
}

/// Representative FAIL record used by crate tests. Synthetic identifiers only.
#[cfg(test)]
pub(crate) fn sample_evidence() -> SecurityEvidence {
    use crate::redaction::RedactionStrategy;
    use time::macros::datetime;

    SecurityEvidence {
        schema: SchemaRef {
            id: "https://darelabs.tech/schemas/evidence".to_owned(),
            version: SchemaVersion::V1,
        },
        id: "urn:uuid:00000000-0000-4000-8000-000000000001".to_owned(),
        vector: VectorRef {
            id: "SYNTHETIC-GENERIC-PERMIT-001".to_owned(),
            version: "1.0.0".to_owned(),
            name: Some("synthetic permit integrity".to_owned()),
        },
        target: TargetRef {
            type_: "synthetic-service".to_owned(),
            id: "synthetic-payment-mcp".to_owned(),
            name: Some("synthetic payment lab".to_owned()),
            software: None,
            software_version: None,
            protocol: None,
            protocol_version: None,
        },
        preconditions: vec![Precondition {
            id: Some("pre-1".to_owned()),
            description: "synthetic lab is isolated".to_owned(),
            satisfied: true,
        }],
        operation: Some(NormalizedOperation {
            kind: "authorization.check".to_owned(),
            name: "transfer".to_owned(),
            resource: Some("payments".to_owned()),
            arguments_digest: Some(sample_hash()),
            attributes: None,
        }),
        authorization_context: Some(AuthorizationContext {
            principal_id: Some("principal-synthetic-001".to_owned()),
            agent_id: Some("agent-synthetic-001".to_owned()),
            authn_method: Some("mtls".to_owned()),
            policy_id: Some("policy-synthetic-001".to_owned()),
            policy_version: Some("1.0.0".to_owned()),
            context_attributes: None,
        }),
        expected: ExpectedOutcome {
            decision: Some(Decision::Deny),
            result: None,
            description: Some("transfer must be denied".to_owned()),
        },
        observed: ObservedOutcome {
            decision: Some(Decision::Allow),
            result: None,
            description: Some("transfer was allowed".to_owned()),
            source: ObservationSource::Fixture,
        },
        verdict: Verdict::Fail,
        severity: Some(SeverityAssessment {
            level: SeverityLevel::High,
            rationale: "deterministic mismatch between expected DENY and observed ALLOW".to_owned(),
        }),
        standards: vec![StandardMapping {
            organization: "Example".to_owned(),
            standard: "Synthetic Controls".to_owned(),
            version: Some("1".to_owned()),
            control: "SC-01".to_owned(),
            url: None,
        }],
        artifacts: vec![EvidenceArtifactRef {
            type_: "log-excerpt".to_owned(),
            uri_or_path: "fixtures/synthetic-payment.ndjson".to_owned(),
            digest: Some(sample_hash()),
            media_type: Some("application/x-ndjson".to_owned()),
            redacted: false,
        }],
        hashes: vec![sample_hash()],
        redaction: RedactionMetadata {
            applied: false,
            strategy: RedactionStrategy::NoneRequired,
            fields: Vec::new(),
        },
        timestamps: EvidenceTimestamps {
            started_at: Some(datetime!(2026-01-15 10:00:00 UTC)),
            observed_at: datetime!(2026-01-15 10:00:01 UTC),
            recorded_at: datetime!(2026-01-15 10:00:02 UTC),
        },
        extensions: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn canonical_model_json_round_trips() {
        let original = sample_evidence();
        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: SecurityEvidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, original);
        let json2 = serde_json::to_string(&decoded).expect("serialize again");
        let decoded2: SecurityEvidence = serde_json::from_str(&json2).expect("deserialize again");
        assert_eq!(decoded2, original);
    }

    #[test]
    fn optional_fields_are_omitted_when_none() {
        let mut evidence = sample_evidence();
        evidence.operation = None;
        evidence.authorization_context = None;
        evidence.severity = None;
        evidence.extensions = None;
        evidence.target.name = None;
        let value = serde_json::to_value(&evidence).unwrap();
        let obj = value.as_object().expect("object");
        assert!(!obj.contains_key("operation"));
        assert!(!obj.contains_key("authorization_context"));
        assert!(!obj.contains_key("severity"));
        assert!(!obj.contains_key("extensions"));
        assert!(!obj["target"].as_object().unwrap().contains_key("name"));
        let back: SecurityEvidence = serde_json::from_value(value).unwrap();
        assert!(back.operation.is_none());
        assert!(back.authorization_context.is_none());
        assert!(back.severity.is_none());
    }

    #[test]
    fn missing_verdict_is_rejected_with_no_default() {
        let mut value = serde_json::to_value(sample_evidence()).unwrap();
        value.as_object_mut().unwrap().remove("verdict");
        let err = serde_json::from_value::<SecurityEvidence>(value).unwrap_err();
        assert!(err.to_string().contains("verdict"));
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let mut value = serde_json::to_value(sample_evidence()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("customer_tenant".to_owned(), json!("acme"));
        assert!(serde_json::from_value::<SecurityEvidence>(value).is_err());
    }

    fn collect_keys(value: &Value, keys: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    keys.push(key.to_lowercase());
                    collect_keys(child, keys);
                }
            }
            Value::Array(items) => {
                for item in items {
                    collect_keys(item, keys);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn authorization_context_has_no_credential_fields() {
        let schema = serde_json::to_value(sample_evidence()).unwrap();
        let mut keys = Vec::new();
        collect_keys(&schema, &mut keys);
        for forbidden in [
            "password",
            "secret",
            "token",
            "api_key",
            "private_key",
            "authorization",
            "bearer",
        ] {
            assert!(
                !keys
                    .iter()
                    .any(|key| key == forbidden || key.ends_with(&format!("_{forbidden}"))),
                "sample evidence must not expose credential field {forbidden}"
            );
        }
        assert!(keys.iter().any(|key| key == "authorization_context"));
    }

    #[test]
    fn decision_and_source_wire_enums() {
        assert_eq!(
            serde_json::to_value(Decision::Allow).unwrap(),
            json!("ALLOW")
        );
        assert_eq!(serde_json::to_value(Decision::Deny).unwrap(), json!("DENY"));
        assert_eq!(
            serde_json::to_value(Decision::ReEvaluate).unwrap(),
            json!("RE_EVALUATE")
        );
        assert_eq!(
            serde_json::to_value(Decision::RequiresApproval).unwrap(),
            json!("REQUIRES_APPROVAL")
        );
        assert_eq!(
            serde_json::to_value(Decision::NotApplicable).unwrap(),
            json!("NOT_APPLICABLE")
        );
        assert_eq!(
            serde_json::to_value(ObservationSource::ProtocolResponse).unwrap(),
            json!("PROTOCOL_RESPONSE")
        );
        assert!(serde_json::from_str::<Decision>("\"PERMIT\"").is_err());
        assert!(serde_json::from_str::<ObservationSource>("\"LLM\"").is_err());
        assert!(serde_json::from_str::<SeverityLevel>("\"SEVERE\"").is_err());
    }

    #[test]
    fn severity_wire_tokens() {
        assert_eq!(
            serde_json::to_value(SeverityLevel::Info).unwrap(),
            json!("INFO")
        );
        assert_eq!(
            serde_json::to_value(SeverityLevel::Low).unwrap(),
            json!("LOW")
        );
        assert_eq!(
            serde_json::to_value(SeverityLevel::Medium).unwrap(),
            json!("MEDIUM")
        );
        assert_eq!(
            serde_json::to_value(SeverityLevel::High).unwrap(),
            json!("HIGH")
        );
        assert_eq!(
            serde_json::to_value(SeverityLevel::Critical).unwrap(),
            json!("CRITICAL")
        );
    }

    #[test]
    fn representative_record_contains_required_contract_keys() {
        let value: Value = serde_json::to_value(sample_evidence()).unwrap();
        for key in [
            "schema",
            "id",
            "vector",
            "target",
            "preconditions",
            "expected",
            "observed",
            "verdict",
            "redaction",
            "timestamps",
        ] {
            assert!(value.get(key).is_some(), "missing {key}");
        }
        assert_eq!(value["schema"]["version"], json!("1.0.0"));
        assert_eq!(value["verdict"], json!("FAIL"));
        assert_eq!(value["redaction"]["strategy"], json!("NONE_REQUIRED"));
    }
}
