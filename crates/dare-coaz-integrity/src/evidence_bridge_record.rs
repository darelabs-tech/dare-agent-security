//! Shared Cycle 001 record assembly for COAZ integrity evidence.

use std::collections::BTreeMap;

use dare_security_evidence::{
    AuthorizationContext, Decision, EvidenceArtifactRef, EvidenceTimestamps, ExpectedOutcome,
    HashRef, NormalizedOperation, ObservationSource, ObservedOutcome, Precondition, SchemaRef,
    SecurityEvidence, SeverityAssessment, SeverityLevel, StandardMapping, TargetRef, VectorRef,
    Verdict,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::binding::digest_json_value;
use crate::result::{
    IntegrityVerdict, ObservedEnforcement, RedactionMetadata, RedactionStrategy, VectorResult,
};
use crate::standards::{reference_key, StandardsSnapshot};
use crate::vector::{ExpectedEnforcement, ReferencePepMode};

use super::context::EmitOptions;
use super::error::EvidenceBridgeError;

/// Canonical schema identity URI required by evidence v1.
pub(super) const EVIDENCE_SCHEMA_ID: &str = "https://darelabs.tech/schemas/evidence";

/// Namespaced extension key for COAZ integrity details.
pub const EXTENSION_KEY: &str = "dare.coaz.integrity";

/// Stable vector version for the Cycle 003 integrity family.
pub const VECTOR_VERSION: &str = "1.0.0";

const SATISFIED_TOKEN: &str = "ENFORCEMENT_SATISFIED";
const SYNTHETIC_TARGET_ID: &str = "synthetic-coaz-integrity-lab";

pub(super) struct RecordInputs<'a> {
    pub result: &'a VectorResult,
    pub options: &'a EmitOptions,
    pub result_digest: HashRef,
}

pub(super) fn timestamps_are_ordered(
    started_at: OffsetDateTime,
    observed_at: OffsetDateTime,
    recorded_at: OffsetDateTime,
) -> bool {
    started_at <= observed_at && observed_at <= recorded_at
}

pub(super) fn safe_text(input: &str) -> String {
    redact_credential_bearing_text(input)
}

pub(super) fn assemble(inputs: RecordInputs<'_>) -> Result<SecurityEvidence, EvidenceBridgeError> {
    let result = inputs.result;
    if !timestamps_are_ordered(
        result.started_at,
        result.finished_at,
        inputs.options.recorded_at,
    ) {
        return Err(EvidenceBridgeError::InvalidTimestamps);
    }

    let extension = build_extension(result, &inputs.result_digest, inputs.options);
    let (expected, observed, verdict, severity) = map_outcomes(result);
    let record_id = deterministic_urn(
        &result.vector_id,
        &result.sink_receipt.operation_name,
        &inputs.result_digest.value,
    );

    let mut extensions = BTreeMap::new();
    extensions.insert(EXTENSION_KEY.to_owned(), extension);

    let evidence = SecurityEvidence {
        schema: SchemaRef {
            id: EVIDENCE_SCHEMA_ID.to_owned(),
            version: dare_security_evidence::SchemaVersion::V1,
        },
        id: record_id,
        vector: VectorRef {
            id: result.vector_id.clone(),
            version: VECTOR_VERSION.to_owned(),
            name: Some(safe_text(&operation_title(result))),
        },
        target: TargetRef {
            type_: "synthetic-service".to_owned(),
            id: SYNTHETIC_TARGET_ID.to_owned(),
            name: Some("synthetic COAZ integrity lab".to_owned()),
            software: Some("dare-coaz-integrity".to_owned()),
            software_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
            protocol: Some("mcp".to_owned()),
            protocol_version: Some("2026-07-28".to_owned()),
        },
        preconditions: vec![
            Precondition {
                id: Some("synthetic-only".to_owned()),
                description: "vector executes against built-in synthetic fixtures only".to_owned(),
                satisfied: true,
            },
            Precondition {
                id: Some("tools-call-scope".to_owned()),
                description: "executable scope is limited to MCP tools/call".to_owned(),
                satisfied: true,
            },
        ],
        operation: Some(build_operation(result, &inputs.result_digest)),
        authorization_context: Some(build_authorization_context(result)),
        expected,
        observed,
        verdict,
        severity,
        standards: standards_from_snapshot(&result.standards),
        artifacts: build_artifacts(inputs.options, &inputs.result_digest),
        hashes: vec![inputs.result_digest.clone()],
        redaction: map_redaction(&result.redaction),
        timestamps: EvidenceTimestamps {
            started_at: Some(result.started_at),
            observed_at: result.finished_at,
            recorded_at: inputs.options.recorded_at,
        },
        extensions: Some(extensions),
    };

    validate_built(&evidence)?;
    Ok(evidence)
}

pub(super) fn result_digest(result: &VectorResult) -> Result<HashRef, EvidenceBridgeError> {
    let value = serde_json::to_value(result).map_err(|_| EvidenceBridgeError::Serialization)?;
    let digest = digest_json_value(&value).map_err(|_| EvidenceBridgeError::ResultDigest)?;
    Ok(HashRef {
        algorithm: "sha256".to_owned(),
        value: digest,
    })
}

fn map_outcomes(
    result: &VectorResult,
) -> (
    ExpectedOutcome,
    ObservedOutcome,
    Verdict,
    Option<SeverityAssessment>,
) {
    let source = ObservationSource::Fixture;
    match result.verdict {
        IntegrityVerdict::Pass => {
            let description = format!(
                "observed enforcement {} satisfied expectation {}",
                enforcement_label(result.observed),
                enforcement_label(result.expected.enforcement)
            );
            (
                ExpectedOutcome {
                    decision: Some(Decision::Allow),
                    result: Some(SATISFIED_TOKEN.to_owned()),
                    description: Some(safe_text(&description)),
                },
                ObservedOutcome {
                    decision: Some(Decision::Allow),
                    result: Some(SATISFIED_TOKEN.to_owned()),
                    description: Some(safe_text(&description)),
                    source,
                },
                Verdict::Pass,
                None,
            )
        }
        IntegrityVerdict::Fail => {
            let expected_token = enforcement_label(result.expected.enforcement);
            let observed_token = enforcement_label(result.observed);
            let description = format!(
                "observed enforcement {observed_token} violated expectation {expected_token}"
            );
            (
                ExpectedOutcome {
                    decision: Some(Decision::Allow),
                    result: Some(expected_token),
                    description: Some(safe_text(&description)),
                },
                ObservedOutcome {
                    decision: Some(Decision::Deny),
                    result: Some(observed_token),
                    description: Some(safe_text(&description)),
                    source,
                },
                Verdict::Fail,
                Some(fail_severity(&description)),
            )
        }
        IntegrityVerdict::Inconclusive => (
            ExpectedOutcome {
                decision: Some(Decision::Allow),
                result: Some(enforcement_label(result.expected.enforcement)),
                description: Some(
                    "deterministic enforcement projection was insufficient for PASS/FAIL"
                        .to_owned(),
                ),
            },
            ObservedOutcome {
                decision: None,
                result: None,
                description: Some(safe_text(&format!(
                    "projection was inconclusive ({})",
                    enforcement_label(result.observed)
                ))),
                source,
            },
            Verdict::Inconclusive,
            None,
        ),
        IntegrityVerdict::Error => (
            ExpectedOutcome {
                decision: None,
                result: None,
                description: Some(
                    "integrity vector must evaluate authorization-to-execution binding".to_owned(),
                ),
            },
            ObservedOutcome {
                decision: None,
                result: None,
                description: Some(safe_text(&format!(
                    "harness infrastructure failure ({})",
                    enforcement_label(result.observed)
                ))),
                source,
            },
            Verdict::Error,
            None,
        ),
    }
}

fn enforcement_label(value: impl SerializeEnforcement) -> String {
    value.enforcement_token()
}

trait SerializeEnforcement {
    fn enforcement_token(&self) -> String;
}

impl SerializeEnforcement for ExpectedEnforcement {
    fn enforcement_token(&self) -> String {
        match self {
            Self::ForwardWithExistingPermit => "FORWARD_WITH_EXISTING_PERMIT".to_owned(),
            Self::ReevaluateOrRefuse => "REEVALUATE_OR_REFUSE".to_owned(),
            Self::PermitRemainsBound => "PERMIT_REMAINS_BOUND".to_owned(),
        }
    }
}

impl SerializeEnforcement for ObservedEnforcement {
    fn enforcement_token(&self) -> String {
        match self {
            Self::ForwardedWithExistingPermit => "FORWARDED_WITH_EXISTING_PERMIT".to_owned(),
            Self::ForwardedAfterReevaluation => "FORWARDED_AFTER_REEVALUATION".to_owned(),
            Self::RefusedAfterBindingChange => "REFUSED_AFTER_BINDING_CHANGE".to_owned(),
            Self::DeniedAfterReevaluation => "DENIED_AFTER_REEVALUATION".to_owned(),
            Self::ForwardedWithStalePermit => "FORWARDED_WITH_STALE_PERMIT".to_owned(),
            Self::NoForwardInitialDeny => "NO_FORWARD_INITIAL_DENY".to_owned(),
            Self::InconclusiveProjection => "INCONCLUSIVE_PROJECTION".to_owned(),
            Self::HarnessError => "HARNESS_ERROR".to_owned(),
        }
    }
}

fn build_operation(result: &VectorResult, digest: &HashRef) -> NormalizedOperation {
    NormalizedOperation {
        kind: "authorization.integrity".to_owned(),
        name: safe_text(&result.sink_receipt.operation_name),
        resource: Some(safe_text(&result.sink_receipt.operation_method)),
        arguments_digest: result
            .sink_receipt
            .params_digest
            .as_ref()
            .map(|value| HashRef {
                algorithm: "sha256".to_owned(),
                value: value.clone(),
            })
            .or_else(|| Some(digest.clone())),
        attributes: None,
    }
}

fn build_authorization_context(result: &VectorResult) -> AuthorizationContext {
    let trusted = &result.initial_projection.trusted_inputs;
    AuthorizationContext {
        principal_id: trusted
            .get("subject_id")
            .and_then(Value::as_str)
            .map(safe_text),
        agent_id: trusted
            .get("agent_id")
            .and_then(Value::as_str)
            .map(safe_text),
        authn_method: None,
        policy_id: Some(result.initial_projection.mapping.id.clone()),
        policy_version: result
            .initial_projection
            .mapping
            .revision
            .clone()
            .or_else(|| Some("1.0.0".to_owned())),
        context_attributes: None,
    }
}

fn build_artifacts(options: &EmitOptions, digest: &HashRef) -> Vec<EvidenceArtifactRef> {
    options
        .result_artifact_path
        .as_ref()
        .map(|path| {
            vec![EvidenceArtifactRef {
                type_: "vector-result".to_owned(),
                uri_or_path: safe_text(path),
                digest: Some(digest.clone()),
                media_type: Some("application/json".to_owned()),
                redacted: false,
            }]
        })
        .unwrap_or_default()
}

fn build_extension(result: &VectorResult, digest: &HashRef, options: &EmitOptions) -> Value {
    json!({
        "vector_id": result.vector_id,
        "expected_enforcement": enforcement_label(result.expected.enforcement),
        "observed_enforcement": enforcement_label(result.observed),
        "reference_mode": reference_mode_token(result.enforcement_trace.reference_mode),
        "binding_changed": result.enforcement_trace.binding_changed,
        "reevaluated": result.enforcement_trace.reevaluated,
        "mutation_kind": mutation_kind_token(result.mutation.kind),
        "standards_schema_version": result.standards.schema_version,
        "result_digest": digest.value,
        "result_artifact_path": options.result_artifact_path.as_ref().map(|path| safe_text(path)),
        "integrity_verdict": integrity_verdict_token(result.verdict),
    })
}

fn standards_from_snapshot(snapshot: &StandardsSnapshot) -> Vec<StandardMapping> {
    snapshot
        .references
        .iter()
        .map(|reference| StandardMapping {
            organization: safe_text(&reference.family),
            standard: safe_text(&reference.document),
            version: Some(safe_text(&reference.version)),
            control: safe_text(&reference_key(reference)),
            url: reference
                .upstream_issue
                .as_ref()
                .map(|issue| safe_text(issue)),
        })
        .collect()
}

fn map_redaction(meta: &RedactionMetadata) -> dare_security_evidence::RedactionMetadata {
    dare_security_evidence::RedactionMetadata {
        applied: meta.applied,
        strategy: match meta.strategy {
            RedactionStrategy::NoneRequired => {
                dare_security_evidence::RedactionStrategy::NoneRequired
            }
            RedactionStrategy::Remove => dare_security_evidence::RedactionStrategy::Remove,
            RedactionStrategy::Mask => dare_security_evidence::RedactionStrategy::Mask,
            RedactionStrategy::Hash => dare_security_evidence::RedactionStrategy::Hash,
            RedactionStrategy::Tokenize => dare_security_evidence::RedactionStrategy::Tokenize,
            RedactionStrategy::Mixed => dare_security_evidence::RedactionStrategy::Mixed,
        },
        fields: meta.fields.clone(),
    }
}

fn operation_title(result: &VectorResult) -> String {
    format!(
        "{} integrity ({})",
        result.sink_receipt.operation_name, result.vector_id
    )
}

fn reference_mode_token(mode: ReferencePepMode) -> &'static str {
    match mode {
        ReferencePepMode::SecureReevaluate => "SECURE_REEVALUATE",
        ReferencePepMode::SecureRefuse => "SECURE_REFUSE",
        ReferencePepMode::VulnerableReuse => "VULNERABLE_REUSE",
    }
}

fn mutation_kind_token(kind: crate::vector::MutationKind) -> &'static str {
    match kind {
        crate::vector::MutationKind::None => "NONE",
        crate::vector::MutationKind::ToolName => "TOOL_NAME",
        crate::vector::MutationKind::MappedArgument => "MAPPED_ARGUMENT",
        crate::vector::MutationKind::Method => "METHOD",
        crate::vector::MutationKind::MappedTrustedContext => "MAPPED_TRUSTED_CONTEXT",
        crate::vector::MutationKind::JsonReorderOnly => "JSON_REORDER_ONLY",
        crate::vector::MutationKind::UnmappedField => "UNMAPPED_FIELD",
    }
}

fn integrity_verdict_token(verdict: IntegrityVerdict) -> &'static str {
    match verdict {
        IntegrityVerdict::Pass => "PASS",
        IntegrityVerdict::Fail => "FAIL",
        IntegrityVerdict::Inconclusive => "INCONCLUSIVE",
        IntegrityVerdict::Error => "ERROR",
    }
}

fn fail_severity(rationale: &str) -> SeverityAssessment {
    SeverityAssessment {
        level: SeverityLevel::Medium,
        rationale: safe_text(rationale),
    }
}

fn deterministic_urn(vector_id: &str, operation_name: &str, result_digest: &str) -> String {
    let digest = sha256_bytes(&[
        vector_id.as_bytes(),
        b"|",
        operation_name.as_bytes(),
        b"|",
        result_digest.as_bytes(),
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

fn redact_credential_bearing_text(input: &str) -> String {
    let mut output = input.to_owned();
    if output.to_ascii_lowercase().contains("bearer ") {
        if let Some(start) = output.to_ascii_lowercase().find("bearer ") {
            let end = output[start..]
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .map(|idx| start + idx)
                .unwrap_or(output.len());
            output.replace_range(start..end, "Bearer [REDACTED]");
        }
    }
    if let Some(scheme_end) = output.find("://") {
        if let Some(at) = output[scheme_end + 3..].find('@') {
            let userinfo_start = scheme_end + 3;
            let userinfo_end = userinfo_start + at;
            if output[userinfo_start..userinfo_end].contains(':') {
                output.replace_range(userinfo_start..userinfo_end, "[REDACTED]");
            }
        }
    }
    output
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{
        sample_vector_result_harness_error, sample_vector_result_inconclusive,
        sample_vector_result_pass, sample_vector_result_stale_permit_fail,
    };

    #[test]
    fn pass_outcomes_are_consistent() {
        let result = sample_vector_result_pass();
        let (expected, observed, verdict, _) = map_outcomes(&result);
        assert_eq!(verdict, Verdict::Pass);
        assert_eq!(expected.decision, observed.decision);
        assert_eq!(expected.result, observed.result);
    }

    #[test]
    fn fail_outcomes_are_consistent() {
        let result = sample_vector_result_stale_permit_fail();
        let (expected, observed, verdict, severity) = map_outcomes(&result);
        assert_eq!(verdict, Verdict::Fail);
        assert_ne!(expected.decision, observed.decision);
        assert!(severity.is_some());
    }

    #[test]
    fn inconclusive_outcomes_are_insufficient() {
        let result = sample_vector_result_inconclusive();
        let (expected, observed, verdict, _) = map_outcomes(&result);
        assert_eq!(verdict, Verdict::Inconclusive);
        assert!(expected.decision.is_some());
        assert!(observed.decision.is_none());
    }

    #[test]
    fn error_outcomes_are_insufficient() {
        let result = sample_vector_result_harness_error();
        let (expected, observed, verdict, _) = map_outcomes(&result);
        assert_eq!(verdict, Verdict::Error);
        assert!(expected.decision.is_none());
        assert!(observed.decision.is_none());
        assert!(observed.description.is_some());
    }
}
