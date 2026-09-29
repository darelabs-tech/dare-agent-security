//! Artifact secret sweep (BLUEPRINT AD-12). The markers and the check live
//! in `dare_attack_graph::v2::sweep` since Cycle 024 (AD-03).
//!
//! The same markers the engine CLIs refuse to write, plus a bearer
//! credential. Every artifact's bytes pass this check before they are
//! written, so a credential that reached an identifier or label cannot leave
//! through `attack-paths`.
pub use dare_attack_graph::v2::sweep::{contains_bearer_credential, is_sensitive, MARKERS};

use crate::error::{Refusal, Result};

pub fn sweep(file: &'static str, bytes: &[u8]) -> Result<()> {
    if is_sensitive(bytes) {
        return Err(Refusal::SensitiveOutput { file }.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_marker_and_a_bearer_credential_is_refused() {
        for marker in MARKERS {
            let bytes = format!("{{\"label\":\"x{marker}y\"}}");
            assert!(
                sweep("attack-graph.json", bytes.as_bytes()).is_err(),
                "{marker}"
            );
        }
        assert!(sweep("summary.md", b"Authorization: Bearer abcdefgh1234").is_err());
        assert!(sweep("summary.md", b"authorization: BEARER abcdefgh1234").is_err());
    }

    #[test]
    fn ordinary_text_passes() {
        assert!(sweep("summary.md", b"the bearer of this path is short").is_ok());
        assert!(sweep("summary.md", b"bearer abc").is_ok());
        assert!(sweep("summary.md", b"node:tool:tool:0123456789ab:export").is_ok());
    }
}
