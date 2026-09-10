//! Protocol negotiation integrity.
//!
//! ```text
//! protocol compatibility != permission to downgrade
//! ```
//!
//! Negotiation finds a version and transport both sides support. That is a
//! compatibility question, and it has nothing to say about whether the version
//! it found is one this deployment is willing to use.
//!
//! A downgrade is only visible if something records what was available. A run
//! that saw `1.0.0` used and knows nothing else has no downgrade to report —
//! and saying "no downgrade" there would be reporting the absence of evidence
//! as evidence of absence.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::message::Exchange;
use crate::policy::A2aPolicy;
use crate::source::TransportKind;

/// What the evidence says about one exchange's protocol negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolAssessment {
    pub message_id: String,
    pub used_version: String,
    pub used_transport: TransportKind,
    /// Whether the version is one policy approves. `None` when policy names
    /// none, which is a gap.
    pub version_approved: Option<bool>,
    /// Whether the transport is one policy approves.
    pub transport_approved: Option<bool>,
    /// Whether the used version is below the policy floor.
    ///
    /// Separate from approval because a downgrade *within* the approved set is
    /// still a downgrade, and an operator wants to know which happened.
    pub below_minimum: Option<bool>,
    /// Versions the peer's card advertised, when a card was supplied.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub advertised_versions: BTreeSet<String>,
}

impl ProtocolAssessment {
    pub fn is_decidable(&self) -> bool {
        self.version_approved.is_some() || self.transport_approved.is_some()
    }
}

/// Assess one exchange's protocol negotiation.
pub fn assess(
    exchange: &Exchange,
    policy: &A2aPolicy,
    advertised_versions: BTreeSet<String>,
) -> ProtocolAssessment {
    let protocol = &policy.protocol_policy;

    let version_approved = (!protocol.approved_versions.is_empty()).then(|| {
        protocol
            .approved_versions
            .contains(&exchange.protocol_version)
    });
    let transport_approved = (!protocol.approved_transports.is_empty())
        .then(|| protocol.approved_transports.contains(&exchange.transport));

    // Version comparison is lexical over dotted components, which is enough for
    // the semver-shaped versions A2A uses and is deliberately not a general
    // semver implementation: a comparison nobody can predict is worse than one
    // that refuses to guess.
    let below_minimum = protocol
        .minimum_version
        .as_deref()
        .map(|minimum| compare_versions(&exchange.protocol_version, minimum).is_lt());

    ProtocolAssessment {
        message_id: exchange.message_id.clone(),
        used_version: exchange.protocol_version.clone(),
        used_transport: exchange.transport,
        version_approved,
        transport_approved,
        below_minimum,
        advertised_versions,
    }
}

/// Compare two dotted version strings component by component.
///
/// Numeric components compare numerically; anything else compares as text. Not
/// a general semver implementation, and deliberately so — pre-release ordering
/// is a place where a clever comparison silently disagrees with a reader.
fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let mut left_parts = left.split('.');
    let mut right_parts = right.split('.');
    loop {
        match (left_parts.next(), right_parts.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(l), Some(r)) => {
                let ordering = match (l.parse::<u64>(), r.parse::<u64>()) {
                    (Ok(l), Ok(r)) => l.cmp(&r),
                    _ => l.cmp(r),
                };
                if ordering != std::cmp::Ordering::Equal {
                    return ordering;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::tests::exchange;
    use crate::policy::tests::policy;

    fn advertised() -> BTreeSet<String> {
        BTreeSet::from(["1.0.0".to_owned(), "0.9.0".to_owned()])
    }

    #[test]
    fn an_approved_version_and_transport_agree() {
        let assessment = assess(&exchange("msg-1"), &policy(), advertised());
        assert_eq!(assessment.version_approved, Some(true));
        assert_eq!(assessment.transport_approved, Some(true));
        assert_eq!(assessment.below_minimum, Some(false));
    }

    #[test]
    fn a_version_below_the_floor_is_a_downgrade() {
        let mut downgraded = exchange("msg-1");
        downgraded.protocol_version = "0.9.0".to_owned();
        let assessment = assess(&downgraded, &policy(), advertised());
        assert_eq!(assessment.below_minimum, Some(true));
        assert_eq!(assessment.version_approved, Some(false));
    }

    #[test]
    fn approval_and_the_floor_are_separate_questions() {
        // A downgrade within the approved set is still a downgrade, and an
        // operator wants to know which of the two happened.
        let mut policy = policy();
        policy
            .protocol_policy
            .approved_versions
            .insert("0.9.0".to_owned());
        let mut downgraded = exchange("msg-1");
        downgraded.protocol_version = "0.9.0".to_owned();

        let assessment = assess(&downgraded, &policy, advertised());
        assert_eq!(assessment.version_approved, Some(true));
        assert_eq!(assessment.below_minimum, Some(true));
    }

    #[test]
    fn an_unapproved_transport_is_reported_separately_from_the_version() {
        let mut other_transport = exchange("msg-1");
        other_transport.transport = crate::source::TransportKind::Grpc;
        let assessment = assess(&other_transport, &policy(), advertised());
        assert_eq!(assessment.version_approved, Some(true));
        assert_eq!(assessment.transport_approved, Some(false));
    }

    #[test]
    fn a_policy_naming_no_versions_leaves_the_question_open() {
        let mut silent = policy();
        silent.protocol_policy.approved_versions = BTreeSet::new();
        silent.protocol_policy.minimum_version = None;
        let assessment = assess(&exchange("msg-1"), &silent, advertised());
        assert_eq!(assessment.version_approved, None);
        assert_eq!(assessment.below_minimum, None);
    }

    #[test]
    fn a_run_that_knows_of_no_alternatives_reports_no_downgrade() {
        // Saying "no downgrade" from an empty advertised set would be reporting
        // the absence of evidence as evidence of absence. The set is recorded
        // so the evaluator can tell the two apart.
        let assessment = assess(&exchange("msg-1"), &policy(), BTreeSet::new());
        assert!(assessment.advertised_versions.is_empty());
        assert_eq!(assessment.version_approved, Some(true));
    }

    #[test]
    fn version_comparison_is_numeric_where_it_can_be() {
        assert!(compare_versions("1.10.0", "1.9.0").is_gt());
        assert!(compare_versions("1.0.0", "1.0.0").is_eq());
        assert!(compare_versions("0.9.0", "1.0.0").is_lt());
        assert!(compare_versions("1.0", "1.0.1").is_lt());
    }
}
