//! Convert discovery observations into Cycle 001 `SecurityEvidence` v1.
//!
//! MCP-specific details belong only in namespaced `extensions` keys
//! (for example `dare.mcp.discovery`). This module does not modify
//! `dare-security-evidence` types or schema.

#[path = "evidence_bridge_error.rs"]
mod error;
#[path = "evidence_bridge_observation.rs"]
mod observation;
#[path = "evidence_bridge_record.rs"]
mod record;
#[path = "evidence_bridge_vectors.rs"]
mod vectors;

pub use error::EvidenceBridgeError;
pub use observation::DiscoveryObservation;
pub use record::{EXTENSION_KEY, VECTOR_VERSION};
pub use vectors::{
    emit_baseline_evidence, emit_completeness_evidence, emit_policy_evidence,
    emit_protocol_evidence, emit_redaction_evidence, VECTOR_COMPLETENESS, VECTOR_POLICY,
    VECTOR_PROTOCOL, VECTOR_REDACTION,
};
