//! Deterministic emitter from validated vector results to Cycle 001 evidence.

use dare_security_evidence::SecurityEvidence;

use crate::result::VectorResult;

use super::context::EmitOptions;
use super::error::EvidenceBridgeError;
use super::record::{assemble, result_digest, RecordInputs};

/// Emits one Cycle 001 `SecurityEvidence` record from a validated vector result.
///
/// COAZ-specific enforcement details remain in the namespaced `extensions`
/// entry [`EXTENSION_KEY`](super::record::EXTENSION_KEY).
pub fn emit_integrity_evidence(
    result: &VectorResult,
    options: &EmitOptions,
) -> Result<SecurityEvidence, EvidenceBridgeError> {
    let digest = result_digest(result)?;
    assemble(RecordInputs {
        result,
        options,
        result_digest: digest,
    })
}
