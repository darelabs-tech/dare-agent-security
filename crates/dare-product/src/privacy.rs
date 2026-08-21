//! Privacy policy for confidential/offline product assessments.

use serde::{Deserialize, Serialize};

use crate::error::{ProductError, Result};

/// High-level privacy posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PrivacyMode {
    #[default]
    Standard,
    Confidential,
}

/// Network posture under the privacy policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    #[default]
    Restricted,
    Denied,
    Allowlisted,
}

/// Central privacy policy controlling telemetry and egress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyPolicy {
    pub mode: PrivacyMode,
    /// Telemetry is always off in v1 product defaults; confidential forces disabled.
    pub telemetry: bool,
    pub network: NetworkMode,
    /// When true, assessment must not open network sockets.
    pub offline: bool,
    #[serde(default)]
    pub retention_days: Option<u32>,
}

impl Default for PrivacyPolicy {
    fn default() -> Self {
        Self {
            mode: PrivacyMode::Standard,
            telemetry: false,
            network: NetworkMode::Restricted,
            offline: false,
            retention_days: Some(30),
        }
    }
}

impl PrivacyPolicy {
    pub fn apply_flags(&mut self, confidential: bool, offline: bool) {
        if confidential {
            self.mode = PrivacyMode::Confidential;
            self.telemetry = false;
            self.network = NetworkMode::Denied;
        }
        if offline {
            self.offline = true;
            self.telemetry = false;
            if self.network != NetworkMode::Denied {
                self.network = NetworkMode::Denied;
            }
        }
    }

    pub fn validate_fail_closed(&self) -> Result<()> {
        if self.telemetry
            && (self.mode == PrivacyMode::Confidential
                || self.offline
                || self.network == NetworkMode::Denied)
        {
            return Err(ProductError::blocked(
                "telemetry cannot be enabled under confidential/offline/denied network mode",
            ));
        }
        if self.mode == PrivacyMode::Confidential && self.network == NetworkMode::Allowlisted {
            return Err(ProductError::blocked(
                "confidential mode refuses allowlisted network; use denied or restricted",
            ));
        }
        Ok(())
    }

    pub fn prohibits_egress(&self) -> bool {
        self.offline
            || self.network == NetworkMode::Denied
            || self.mode == PrivacyMode::Confidential
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidential_forces_no_telemetry() {
        let mut p = PrivacyPolicy {
            telemetry: true,
            ..Default::default()
        };
        p.apply_flags(true, false);
        assert!(!p.telemetry);
        assert!(p.prohibits_egress());
        assert!(p.validate_fail_closed().is_ok());
    }

    #[test]
    fn telemetry_blocked_when_offline() {
        let p = PrivacyPolicy {
            telemetry: true,
            offline: true,
            ..Default::default()
        };
        assert!(p.validate_fail_closed().is_err());
    }
}
