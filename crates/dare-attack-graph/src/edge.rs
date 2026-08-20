use serde::{Deserialize, Serialize};

use crate::authority::AuthorityContext;
use crate::canonical::digest_value;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EdgeType {
    AuthenticatesAs,
    DelegatesTo,
    CanInvoke,
    Calls,
    UsesCredential,
    AuthorizedBy,
    EnforcedBy,
    Reads,
    Writes,
    Deletes,
    TransfersTo,
    BelongsToTenant,
    CrossesTrustBoundary,
    CanReach,
}

pub fn build_edge_id(
    source: &str,
    edge_type: EdgeType,
    target: &str,
    authority: &AuthorityContext,
) -> Result<String> {
    let mut authority = authority.clone();
    authority.normalize();
    let value = serde_json::json!({
        "authority": authority,
        "source": source,
        "target": target,
        "type": edge_type,
    });
    Ok(format!("edge:{}", digest_value(&value)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_order_does_not_change_edge_id() {
        let a = AuthorityContext {
            scopes: vec!["write".into(), "read".into()],
            ..AuthorityContext::default()
        };
        let b = AuthorityContext {
            scopes: vec!["read".into(), "write".into()],
            ..AuthorityContext::default()
        };
        assert_eq!(
            build_edge_id("a", EdgeType::Calls, "b", &a).unwrap(),
            build_edge_id("a", EdgeType::Calls, "b", &b).unwrap()
        );
    }
}
