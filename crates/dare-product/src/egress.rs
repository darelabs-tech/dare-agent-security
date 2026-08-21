//! Fail-closed egress helpers for offline/confidential assessments.

use crate::error::{ProductError, Result};
use crate::privacy::PrivacyPolicy;

/// Declared destination class for any network-capable subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkClass {
    Loopback,
    Private,
    Public,
    Telemetry,
    ModelApi,
}

/// Guard that records attempted egress and refuses prohibited classes.
#[derive(Debug, Default)]
pub struct EgressGuard {
    attempts: Vec<(NetworkClass, String)>,
    deny_all: bool,
}

impl EgressGuard {
    pub fn from_policy(policy: &PrivacyPolicy) -> Self {
        Self {
            attempts: Vec::new(),
            deny_all: policy.prohibits_egress(),
        }
    }

    pub fn deny_all() -> Self {
        Self {
            attempts: Vec::new(),
            deny_all: true,
        }
    }

    /// Record and validate an intended network action. Fail-closed when denied.
    pub fn check(&mut self, class: NetworkClass, purpose: impl Into<String>) -> Result<()> {
        let purpose = purpose.into();
        self.attempts.push((class, purpose.clone()));
        if !self.deny_all {
            return Ok(());
        }
        Err(ProductError::blocked(format!(
            "egress denied in offline/confidential mode (class={class:?}, purpose={purpose})"
        )))
    }

    pub fn attempt_count(&self) -> usize {
        self.attempts.len()
    }

    pub fn denied(&self) -> bool {
        self.deny_all
    }
}

/// Assert that an offline assessment path never requests prohibited egress.
pub fn assert_offline_allowed(policy: &PrivacyPolicy) -> Result<()> {
    if !policy.prohibits_egress() {
        return Ok(());
    }
    if policy.telemetry {
        return Err(ProductError::blocked(
            "offline/confidential assessment cannot enable telemetry",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::{NetworkMode, PrivacyMode, PrivacyPolicy};

    #[test]
    fn offline_denies_public_and_telemetry() {
        let policy = PrivacyPolicy {
            mode: PrivacyMode::Confidential,
            telemetry: false,
            network: NetworkMode::Denied,
            offline: true,
            retention_days: None,
        };
        let mut guard = EgressGuard::from_policy(&policy);
        assert!(guard
            .check(NetworkClass::Telemetry, "crash-upload")
            .is_err());
        assert!(guard.check(NetworkClass::ModelApi, "remote-llm").is_err());
        assert!(guard.check(NetworkClass::Public, "update-check").is_err());
        assert_eq!(guard.attempt_count(), 3);
    }

    #[test]
    fn standard_allows_recorded_egress() {
        let policy = PrivacyPolicy::default();
        let mut guard = EgressGuard::from_policy(&policy);
        assert!(guard.check(NetworkClass::Loopback, "local-mcp").is_ok());
    }
}
