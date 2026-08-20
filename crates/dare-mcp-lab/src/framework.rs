//! Shared synthetic lab framework primitives (Cycle 005 task-003).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::error::LabError;

static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

/// Secure or vulnerable implementation variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VariantKind {
    Secure,
    Vulnerable,
}

impl VariantKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Secure => "secure",
            Self::Vulnerable => "vulnerable",
        }
    }
}

/// Synthetic principal / agent / service identity (never a real account).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabIdentity {
    pub id: String,
    pub kind: String,
    pub display_name: String,
}

impl LabIdentity {
    pub fn human(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: "human".to_owned(),
            display_name: "synthetic-human".to_owned(),
        }
    }

    pub fn agent(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: "agent".to_owned(),
            display_name: "synthetic-agent".to_owned(),
        }
    }

    pub fn service(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            kind: "service".to_owned(),
            display_name: "synthetic-service".to_owned(),
        }
    }
}

/// Local-only synthetic credential handle — never a live secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabCredential {
    pub id: String,
    pub issuer: String,
    pub subject: String,
    pub token_material: String,
}

impl LabCredential {
    pub fn synthetic(issuer: &str, subject: &str) -> Self {
        Self {
            id: format!("cred-{issuer}-{subject}"),
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            // Deliberately non-secret placeholder; must never look like a live token.
            token_material: format!("synthetic-token:{issuer}:{subject}"),
        }
    }

    pub fn looks_like_live_secret(&self) -> bool {
        let t = &self.token_material;
        t.starts_with("sk-live-")
            || t.starts_with("Bearer ")
            || t.contains("password=")
            || t.starts_with("ghp_")
    }
}

/// Deterministic policy fixture decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDecision {
    Permit,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyFixture {
    pub id: String,
    pub decision: PolicyDecision,
    pub bound_action: String,
    pub bound_resource: String,
    pub bound_subject: String,
}

impl PolicyFixture {
    pub fn permit(action: &str, resource: &str, subject: &str) -> Self {
        Self {
            id: format!("policy-{action}-{resource}"),
            decision: PolicyDecision::Permit,
            bound_action: action.to_owned(),
            bound_resource: resource.to_owned(),
            bound_subject: subject.to_owned(),
        }
    }
}

/// Ephemeral in-memory lab state keyed by session.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LabState {
    entries: BTreeMap<String, String>,
}

impl LabState {
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.entries.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries.get(key).map(String::as_str)
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Isolated lab session with deterministic addressing and teardown.
#[derive(Debug)]
pub struct LabSession {
    pub session_id: String,
    pub variant: VariantKind,
    pub scenario_id: String,
    pub identities: Vec<LabIdentity>,
    pub credentials: Vec<LabCredential>,
    pub policy: Option<PolicyFixture>,
    pub state: LabState,
    pub endpoint: String,
    active: bool,
}

impl LabSession {
    /// Start a new isolated session. Endpoint is local-only (`lab://…`).
    pub fn start(scenario_id: impl Into<String>, variant: VariantKind) -> Result<Self, LabError> {
        let scenario_id = scenario_id.into();
        let seq = SESSION_SEQ.fetch_add(1, Ordering::SeqCst);
        let session_id = format!("{}-{}-{seq}", scenario_id.to_lowercase(), variant.as_str());
        Ok(Self {
            endpoint: format!("lab://{session_id}"),
            session_id,
            variant,
            scenario_id,
            identities: Vec::new(),
            credentials: Vec::new(),
            policy: None,
            state: LabState::default(),
            active: true,
        })
    }

    pub fn with_identity(mut self, identity: LabIdentity) -> Self {
        self.identities.push(identity);
        self
    }

    pub fn with_credential(mut self, credential: LabCredential) -> Result<Self, LabError> {
        if credential.looks_like_live_secret() {
            return Err(LabError::SafetyPolicy {
                reason: "refusing live-looking credential material in lab fixtures".to_owned(),
            });
        }
        self.credentials.push(credential);
        Ok(self)
    }

    pub fn with_policy(mut self, policy: PolicyFixture) -> Self {
        self.policy = Some(policy);
        self
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Reset mutable state without ending the session.
    pub fn reset(&mut self) {
        self.state.clear();
    }

    /// Tear down the session. Idempotent.
    pub fn teardown(mut self) -> LabState {
        self.active = false;
        let mut state = std::mem::take(&mut self.state);
        state.clear();
        self.identities.clear();
        self.credentials.clear();
        self.policy = None;
        state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_are_isolated_and_repeatable() {
        let mut a = LabSession::start("MCP-LAB-001", VariantKind::Secure).unwrap();
        a.state.insert("k", "v1");
        let mut b = LabSession::start("MCP-LAB-001", VariantKind::Secure).unwrap();
        b.state.insert("k", "v2");
        assert_ne!(a.session_id, b.session_id);
        assert_ne!(a.endpoint, b.endpoint);
        assert_eq!(a.state.get("k"), Some("v1"));
        assert_eq!(b.state.get("k"), Some("v2"));
        a.teardown();
        b.reset();
        assert!(b.state.is_empty());
        b.teardown();
    }

    #[test]
    fn refuses_live_looking_credentials() {
        let bad = LabCredential {
            id: "x".to_owned(),
            issuer: "evil".to_owned(),
            subject: "x".to_owned(),
            token_material: "sk-live-abcdef".to_owned(),
        };
        let err = LabSession::start("MCP-LAB-001", VariantKind::Vulnerable)
            .unwrap()
            .with_credential(bad)
            .expect_err("must refuse");
        assert!(matches!(err, LabError::SafetyPolicy { .. }));
    }
}
