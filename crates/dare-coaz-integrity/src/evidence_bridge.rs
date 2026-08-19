//! Convert validated vector results into Cycle 001 `SecurityEvidence` v1.
//!
//! COAZ-specific details belong only in namespaced `extensions` keys
//! (for example `dare.coaz.integrity`). This module does not modify
//! `dare-security-evidence` types or schema.

#[path = "evidence_bridge_context.rs"]
mod context;
#[path = "evidence_bridge_error.rs"]
mod error;
#[path = "evidence_bridge_record.rs"]
mod record;
#[path = "evidence_bridge_vectors.rs"]
mod vectors;

pub use context::EmitOptions;
pub use error::EvidenceBridgeError;
pub use record::{EXTENSION_KEY, VECTOR_VERSION};
pub use vectors::emit_integrity_evidence;
