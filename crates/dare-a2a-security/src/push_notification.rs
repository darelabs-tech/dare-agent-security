//! The push-notification boundary.
//!
//! ```text
//! webhook URL != permission to connect
//! ```
//!
//! A push-notification configuration is a URL by construction, and the
//! temptation to check whether it resolves is exactly what this module refuses.
//! Nothing here connects, probes, resolves DNS or sends a test callback. The
//! destination is compared as a **string** against what policy approved.
//!
//! That is not a weaker check than connecting — it is a different one. Whether
//! the host answers says nothing about whether the deployment approved sending
//! data there, and the second question is the one that matters.

use serde::{Deserialize, Serialize};

use crate::canonical::assert_safe_identifier;
use crate::error::Result;
use crate::policy::A2aPolicy;
use crate::source::{DataSensitivity, EvidenceSource, VerificationStatus};

/// A push-notification configuration, read as local data.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotificationConfig {
    pub config_id: String,
    /// The destination. Inert metadata: compared as a string, contacted by
    /// nothing.
    pub destination: String,
    /// The tenant the configuration belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// The most sensitive label this configuration would send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sensitivity: Option<DataSensitivity>,
    /// Whether a verifier recorded that the destination was validated.
    ///
    /// A status somebody else recorded. This engine performs no validation and
    /// `UNRECORDED` is the honest default.
    #[serde(default = "unrecorded")]
    pub destination_verification: VerificationStatus,
    pub evidence_source: EvidenceSource,
}

fn unrecorded() -> VerificationStatus {
    VerificationStatus::Unrecorded
}

impl PushNotificationConfig {
    pub fn validate(&self) -> Result<()> {
        assert_safe_identifier(&self.config_id, "a push config id")?;
        if let Some(tenant) = &self.tenant {
            assert_safe_identifier(tenant, "a push config tenant")?;
        }
        Ok(())
    }
}

/// What the evidence says about one push-notification configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushNotificationAssessment {
    pub config_id: String,
    pub destination: String,
    /// Whether the destination is one policy approved. `None` when policy names
    /// none, which is a gap.
    pub destination_approved: Option<bool>,
    /// Whether the configuration stays within the policy's sensitivity ceiling.
    pub within_sensitivity_ceiling: Option<bool>,
    /// Whether a verifier recorded a destination validation.
    pub destination_verification: VerificationStatus,
}

impl PushNotificationAssessment {
    pub fn is_decidable(&self) -> bool {
        self.destination_approved.is_some()
    }
}

/// Assess one push-notification configuration.
pub fn assess(config: &PushNotificationConfig, policy: &A2aPolicy) -> PushNotificationAssessment {
    let push = &policy.push_notification_policy;

    let destination_approved = (!push.approved_destinations.is_empty())
        .then(|| push.approved_destinations.contains(&config.destination));

    let within_sensitivity_ceiling = match (config.max_sensitivity, push.max_sensitivity) {
        (Some(configured), Some(ceiling)) => Some(configured <= ceiling),
        _ => None,
    };

    PushNotificationAssessment {
        config_id: config.config_id.clone(),
        destination: config.destination.clone(),
        destination_approved,
        within_sensitivity_ceiling,
        destination_verification: config.destination_verification,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::policy::tests::policy;

    pub(crate) fn config(destination: &str) -> PushNotificationConfig {
        PushNotificationConfig {
            config_id: "push-1".to_owned(),
            destination: destination.to_owned(),
            tenant: Some("tenant-a".to_owned()),
            max_sensitivity: Some(DataSensitivity::Internal),
            destination_verification: VerificationStatus::Unrecorded,
            evidence_source: EvidenceSource::CapturedTrace,
        }
    }

    #[test]
    fn an_approved_destination_agrees() {
        let assessment = assess(&config("https://callback.example/hook"), &policy());
        assert_eq!(assessment.destination_approved, Some(true));
        assert_eq!(assessment.within_sensitivity_ceiling, Some(true));
    }

    #[test]
    fn an_unapproved_destination_is_a_finding_without_anything_being_contacted() {
        // The comparison is a string comparison. Whether the host answers says
        // nothing about whether the deployment approved sending data there.
        let assessment = assess(&config("https://attacker.example/collect"), &policy());
        assert_eq!(assessment.destination_approved, Some(false));
    }

    #[test]
    fn a_configuration_above_the_sensitivity_ceiling_is_a_widening() {
        let mut widened = config("https://callback.example/hook");
        widened.max_sensitivity = Some(DataSensitivity::Restricted);
        assert_eq!(
            assess(&widened, &policy()).within_sensitivity_ceiling,
            Some(false)
        );
    }

    #[test]
    fn the_default_verification_status_is_unrecorded() {
        // This engine validates no destination. `UNRECORDED` is the honest
        // default, and it can never satisfy positive evidence.
        let config = config("https://callback.example/hook");
        assert_eq!(
            config.destination_verification,
            VerificationStatus::Unrecorded
        );
        assert!(!config
            .destination_verification
            .may_satisfy_positive_evidence());
    }

    #[test]
    fn a_policy_naming_no_destinations_leaves_the_question_open() {
        let mut silent = policy();
        silent.push_notification_policy.approved_destinations = Default::default();
        let assessment = assess(&config("https://callback.example/hook"), &silent);
        assert_eq!(assessment.destination_approved, None);
        assert!(!assessment.is_decidable());
    }

    #[test]
    fn a_configuration_carries_no_credential_for_the_callback() {
        // Structural: there is nowhere to put one. A webhook secret in a
        // configuration this engine reads would be a credential in a document
        // that exists to be analyzed.
        let hostile = serde_json::json!({
            "config_id": "push-1", "destination": "https://callback.example/hook",
            "evidence_source": "CAPTURED_TRACE", "token": "x"
        });
        assert!(serde_json::from_value::<PushNotificationConfig>(hostile).is_err());
    }
}
