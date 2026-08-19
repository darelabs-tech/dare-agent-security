//! Deterministic emitters for the initial MCP discovery evidence vectors.

use std::collections::BTreeMap;

use dare_security_evidence::{Decision, ObservationSource, SecurityEvidence, Verdict};
use serde_json::{json, Value};

use super::error::EvidenceBridgeError;
use super::observation::DiscoveryObservation;
use super::record::{
    assemble, build_extension, error_outcomes, expected_allow, fail_severity,
    inconclusive_outcomes, observed_decision, safe_error, RecordPlan,
};
use crate::adapter::{documented_wire_revision, CURRENT_WIRE_REVISION, LEGACY_WIRE_REVISION};
use crate::inventory::{Completeness, DiscoveryInventory, RedactionStrategy};
use crate::policy::{DefaultPolicy, PassivePolicy};
use crate::sanitize::{looks_like_secret_value, sanitize_inventory};

/// Vector: protocol negotiation/selection.
pub const VECTOR_PROTOCOL: &str = "MCP-DISCOVERY-001";
/// Vector: passive-method policy enforcement.
pub const VECTOR_POLICY: &str = "MCP-DISCOVERY-002";
/// Vector: inventory completeness/partial status.
pub const VECTOR_COMPLETENESS: &str = "MCP-DISCOVERY-003";
/// Vector: credential redaction property.
pub const VECTOR_REDACTION: &str = "MCP-DISCOVERY-004";

/// Emit the four initial baseline evidence records for one observation.
pub fn emit_baseline_evidence(
    observation: &DiscoveryObservation,
) -> Result<Vec<SecurityEvidence>, EvidenceBridgeError> {
    Ok(vec![
        emit_protocol_evidence(observation)?,
        emit_policy_evidence(observation)?,
        emit_completeness_evidence(observation)?,
        emit_redaction_evidence(observation)?,
    ])
}

/// MCP-DISCOVERY-001: negotiated/selected protocol revision.
pub fn emit_protocol_evidence(
    observation: &DiscoveryObservation,
) -> Result<SecurityEvidence, EvidenceBridgeError> {
    let expected_revision = documented_wire_revision(observation.policy_profile);
    let extra = extra_map(&[("expected_revision", json!(expected_revision))]);
    let extension = build_extension(observation, "protocol-negotiated", extra);
    let source = ObservationSource::ProtocolResponse;

    let Some(inventory) = observation.inventory.as_ref() else {
        return assemble_missing(MissingPlan {
            observation,
            vector_id: VECTOR_PROTOCOL,
            vector_code: "protocol-negotiated",
            vector_name: "protocol-negotiated",
            expected_description: "supported protocol revision must be selected or negotiated",
            missing_description: "protocol revision was not observed",
            source,
            extension,
        });
    };

    let observed_revision = inventory.protocol.revision.trim();
    if observed_revision.is_empty() {
        let (expected, observed) = inconclusive_outcomes(
            "supported protocol revision must be selected or negotiated",
            "protocol revision was empty so the vector is inconclusive",
            source,
        );
        return assemble(
            observation,
            RecordPlan {
                vector_id: VECTOR_PROTOCOL,
                vector_name: "protocol-negotiated",
                vector_code: "protocol-negotiated",
                expected,
                observed,
                verdict: Verdict::Inconclusive,
                extension,
                severity: None,
            },
        );
    }

    let observed_decision_value = if is_supported_revision(observed_revision) {
        Decision::Allow
    } else {
        Decision::Deny
    };
    let match_selected = observed_revision == expected_revision;
    let verdict = if match_selected && observed_decision_value == Decision::Allow {
        Verdict::Pass
    } else {
        Verdict::Fail
    };
    let description = if verdict == Verdict::Pass {
        format!("protocol revision {observed_revision} was selected")
    } else if !is_supported_revision(observed_revision) {
        "observed protocol revision is not a supported discovery revision".to_owned()
    } else {
        "observed protocol revision does not match the selected policy profile".to_owned()
    };

    assemble(
        observation,
        RecordPlan {
            vector_id: VECTOR_PROTOCOL,
            vector_name: "protocol-negotiated",
            vector_code: "protocol-negotiated",
            expected: expected_allow(
                expected_revision,
                "supported protocol revision must be selected or negotiated",
            ),
            observed: observed_decision(
                observed_decision_value,
                observed_revision,
                &description,
                source,
            ),
            verdict,
            extension,
            severity: (verdict == Verdict::Fail)
                .then(|| fail_severity("protocol revision does not match the selected profile")),
        },
    )
}

/// MCP-DISCOVERY-002: only allowlisted methods reached transport.
pub fn emit_policy_evidence(
    observation: &DiscoveryObservation,
) -> Result<SecurityEvidence, EvidenceBridgeError> {
    let extra = extra_map(&[]);
    let extension = build_extension(observation, "passive-method-policy", extra);
    let source = ObservationSource::PolicyEngine;
    let policy = DefaultPolicy::new(observation.policy_profile);

    if observation.invoked_methods.is_empty() {
        return assemble_missing(MissingPlan {
            observation,
            vector_id: VECTOR_POLICY,
            vector_code: "passive-method-policy",
            vector_name: "passive-method-policy",
            expected_description: "only allowlisted passive methods may be invoked",
            missing_description: "no outbound methods were observed",
            source,
            extension,
        });
    }

    let allowlist_honored = observation
        .invoked_methods
        .iter()
        .all(|method| policy.authorize(method).is_ok());

    if allowlist_honored {
        assemble(
            observation,
            RecordPlan {
                vector_id: VECTOR_POLICY,
                vector_name: "passive-method-policy",
                vector_code: "passive-method-policy",
                expected: expected_allow(
                    "ALLOWLIST_HONORED",
                    "only allowlisted passive methods may be invoked",
                ),
                observed: observed_decision(
                    Decision::Allow,
                    "ALLOWLIST_HONORED",
                    "all observed outbound methods were allowlisted",
                    source,
                ),
                verdict: Verdict::Pass,
                extension,
                severity: None,
            },
        )
    } else {
        assemble(
            observation,
            RecordPlan {
                vector_id: VECTOR_POLICY,
                vector_name: "passive-method-policy",
                vector_code: "passive-method-policy",
                expected: expected_allow(
                    "ALLOWLIST_HONORED",
                    "only allowlisted passive methods may be invoked",
                ),
                observed: observed_decision(
                    Decision::Deny,
                    "NON_ALLOWLISTED_METHOD",
                    "one or more observed outbound methods were not allowlisted",
                    source,
                ),
                verdict: Verdict::Fail,
                extension,
                severity: Some(fail_severity(
                    "passive policy observed a non-allowlisted outbound method",
                )),
            },
        )
    }
}

/// MCP-DISCOVERY-003: inventory completeness versus a complete baseline.
pub fn emit_completeness_evidence(
    observation: &DiscoveryObservation,
) -> Result<SecurityEvidence, EvidenceBridgeError> {
    let extra = extra_map(&[]);
    let extension = build_extension(observation, "inventory-completeness", extra);
    let source = ObservationSource::ProtocolResponse;

    let Some(inventory) = observation.inventory.as_ref() else {
        return assemble_missing(MissingPlan {
            observation,
            vector_id: VECTOR_COMPLETENESS,
            vector_code: "inventory-completeness",
            vector_name: "inventory-completeness",
            expected_description: "discovery inventory must complete within configured bounds",
            missing_description: "inventory completeness was not observed",
            source,
            extension,
        });
    };

    match inventory.completeness {
        Completeness::Complete => assemble(
            observation,
            RecordPlan {
                vector_id: VECTOR_COMPLETENESS,
                vector_name: "inventory-completeness",
                vector_code: "inventory-completeness",
                expected: expected_allow(
                    "COMPLETE",
                    "discovery inventory must complete within configured bounds",
                ),
                observed: observed_decision(
                    Decision::Allow,
                    "COMPLETE",
                    "inventory completeness is COMPLETE",
                    source,
                ),
                verdict: Verdict::Pass,
                extension,
                severity: None,
            },
        ),
        Completeness::Partial => assemble(
            observation,
            RecordPlan {
                vector_id: VECTOR_COMPLETENESS,
                vector_name: "inventory-completeness",
                vector_code: "inventory-completeness",
                expected: expected_allow(
                    "COMPLETE",
                    "discovery inventory must complete within configured bounds",
                ),
                observed: observed_decision(
                    Decision::Allow,
                    "PARTIAL",
                    "inventory completeness is PARTIAL",
                    source,
                ),
                verdict: Verdict::Fail,
                extension,
                severity: Some(fail_severity(
                    "inventory stopped before completing within configured bounds",
                )),
            },
        ),
    }
}

/// MCP-DISCOVERY-004: inventory must not retain raw credentials.
pub fn emit_redaction_evidence(
    observation: &DiscoveryObservation,
) -> Result<SecurityEvidence, EvidenceBridgeError> {
    let extra = extra_map(&[]);
    let extension = build_extension(observation, "credential-redaction", extra);
    let source = ObservationSource::ProtocolResponse;

    let Some(inventory) = observation.inventory.as_ref() else {
        return assemble_missing(MissingPlan {
            observation,
            vector_id: VECTOR_REDACTION,
            vector_code: "credential-redaction",
            vector_name: "credential-redaction",
            expected_description: "inventory must not retain raw credentials",
            missing_description: "inventory was not observed so redaction cannot be proven",
            source,
            extension,
        });
    };

    if redaction_metadata_incoherent(inventory) {
        let (expected, observed) = inconclusive_outcomes(
            "inventory must not retain raw credentials",
            "inventory redaction metadata is incoherent so the vector is inconclusive",
            source,
        );
        return assemble(
            observation,
            RecordPlan {
                vector_id: VECTOR_REDACTION,
                vector_name: "credential-redaction",
                vector_code: "credential-redaction",
                expected,
                observed,
                verdict: Verdict::Inconclusive,
                extension,
                severity: None,
            },
        );
    }

    let leaked = inventory_has_secret_like(inventory) || unsanitized_identity(inventory);
    if leaked {
        assemble(
            observation,
            RecordPlan {
                vector_id: VECTOR_REDACTION,
                vector_name: "credential-redaction",
                vector_code: "credential-redaction",
                expected: expected_allow(
                    "CREDENTIAL_FREE",
                    "inventory must not retain raw credentials",
                ),
                observed: observed_decision(
                    Decision::Deny,
                    "SECRET_LIKE_PRESENT",
                    "inventory retained secret-like material or an unsanitized identity",
                    source,
                ),
                verdict: Verdict::Fail,
                extension,
                severity: Some(fail_severity(
                    "credential redaction property failed without copying secrets into evidence",
                )),
            },
        )
    } else {
        assemble(
            observation,
            RecordPlan {
                vector_id: VECTOR_REDACTION,
                vector_name: "credential-redaction",
                vector_code: "credential-redaction",
                expected: expected_allow(
                    "CREDENTIAL_FREE",
                    "inventory must not retain raw credentials",
                ),
                observed: observed_decision(
                    Decision::Allow,
                    "CREDENTIAL_FREE",
                    "inventory did not retain secret-like material",
                    source,
                ),
                verdict: Verdict::Pass,
                extension,
                severity: None,
            },
        )
    }
}

struct MissingPlan<'a> {
    observation: &'a DiscoveryObservation,
    vector_id: &'static str,
    vector_code: &'static str,
    vector_name: &'static str,
    expected_description: &'static str,
    missing_description: &'static str,
    source: ObservationSource,
    extension: Value,
}

fn assemble_missing(plan: MissingPlan<'_>) -> Result<SecurityEvidence, EvidenceBridgeError> {
    if let Some(error) = plan.observation.evaluation_error.as_deref() {
        let (expected, observed) = error_outcomes(
            plan.expected_description,
            &format!("vector could not be evaluated ({})", safe_error(error)),
            plan.source,
        );
        return assemble(
            plan.observation,
            RecordPlan {
                vector_id: plan.vector_id,
                vector_name: plan.vector_name,
                vector_code: plan.vector_code,
                expected,
                observed,
                verdict: Verdict::Error,
                extension: plan.extension,
                severity: None,
            },
        );
    }

    let (expected, observed) = inconclusive_outcomes(
        plan.expected_description,
        plan.missing_description,
        plan.source,
    );
    assemble(
        plan.observation,
        RecordPlan {
            vector_id: plan.vector_id,
            vector_name: plan.vector_name,
            vector_code: plan.vector_code,
            expected,
            observed,
            verdict: Verdict::Inconclusive,
            extension: plan.extension,
            severity: None,
        },
    )
}

fn is_supported_revision(revision: &str) -> bool {
    revision == CURRENT_WIRE_REVISION || revision == LEGACY_WIRE_REVISION
}

fn extra_map(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

fn redaction_metadata_incoherent(inventory: &DiscoveryInventory) -> bool {
    match (inventory.redaction.applied, inventory.redaction.strategy) {
        (false, RedactionStrategy::None) => false,
        (true, RedactionStrategy::Partial | RedactionStrategy::Full) => false,
        (true, RedactionStrategy::None)
        | (false, RedactionStrategy::Partial | RedactionStrategy::Full) => true,
    }
}

fn unsanitized_identity(inventory: &DiscoveryInventory) -> bool {
    let mut clone = inventory.clone();
    sanitize_inventory(&mut clone) && !inventory.redaction.applied
}

fn inventory_has_secret_like(inventory: &DiscoveryInventory) -> bool {
    match serde_json::to_value(inventory) {
        Ok(value) => json_has_secret_like(&value),
        Err(_) => true,
    }
}

fn json_has_secret_like(value: &Value) -> bool {
    match value {
        Value::String(raw) => string_looks_credential_bearing(raw),
        Value::Object(map) => map.values().any(json_has_secret_like),
        Value::Array(items) => items.iter().any(json_has_secret_like),
        _ => false,
    }
}

fn string_looks_credential_bearing(raw: &str) -> bool {
    looks_like_secret_value(raw) || raw.to_ascii_lowercase().contains("bearer ")
}
