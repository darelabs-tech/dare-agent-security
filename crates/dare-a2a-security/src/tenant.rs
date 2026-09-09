//! The tenant boundary.
//!
//! ```text
//! tenant routing value != proof of tenant authorization
//! ```
//!
//! A message carries `tenant: tenant-a` because the sender put it there. It is
//! a routing value, and reading it as authorization is the whole vulnerability:
//! an attacker who can set a field would then be an attacker who can choose a
//! tenant.
//!
//! So the claim is compared against what the **local policy** says the subject
//! actually belongs to. Cycle 015 owns tenant identity semantics generally;
//! this module evaluates only their A2A projection.

use serde::{Deserialize, Serialize};

use crate::message::Exchange;
use crate::peer::PeerIdentity;
use crate::policy::A2aPolicy;

/// What the evidence says about one exchange's tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantAssessment {
    pub message_id: String,
    pub peer_id: String,
    /// What the message claimed. A routing value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_tenant: Option<String>,
    /// What policy says the subject belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_tenant: Option<String>,
    /// Whether the claim matches the policy. `None` when either side is silent.
    pub claim_matches_policy: Option<bool>,
    /// Whether the tenant may reach this peer at all.
    pub tenant_may_reach_peer: Option<bool>,
}

impl TenantAssessment {
    pub fn is_decidable(&self) -> bool {
        self.claim_matches_policy.is_some()
    }
}

/// Assess one exchange's tenant boundary.
pub fn assess(
    exchange: &Exchange,
    peer: Option<&PeerIdentity>,
    policy: &A2aPolicy,
) -> TenantAssessment {
    let subject = peer.and_then(PeerIdentity::authorization_subject);
    let policy_tenant = subject
        .and_then(|subject| policy.tenant_policy.tenant_of(subject))
        .map(ToOwned::to_owned);

    let claimed_tenant = exchange.tenant_claim.clone();
    let claim_matches_policy = match (&claimed_tenant, &policy_tenant) {
        (Some(claimed), Some(actual)) => Some(claimed == actual),
        _ => None,
    };

    // Reachability is asked about the tenant the *policy* named, never the one
    // the message claimed. Asking about the claim would let the claim answer
    // its own question.
    let tenant_may_reach_peer = policy_tenant.as_deref().and_then(|tenant| {
        policy
            .tenant_policy
            .tenant_may_reach(tenant, &exchange.peer_id)
    });

    TenantAssessment {
        message_id: exchange.message_id.clone(),
        peer_id: exchange.peer_id.clone(),
        claimed_tenant,
        policy_tenant,
        claim_matches_policy,
        tenant_may_reach_peer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::tests::exchange;
    use crate::peer::tests::peer;
    use crate::policy::tests::policy;

    #[test]
    fn a_claim_matching_the_policy_tenant_agrees() {
        let assessment = assess(&exchange("msg-1"), Some(&peer("planner")), &policy());
        assert_eq!(assessment.claim_matches_policy, Some(true));
        assert_eq!(assessment.tenant_may_reach_peer, Some(true));
        assert!(assessment.is_decidable());
    }

    #[test]
    fn a_claimed_tenant_the_subject_does_not_belong_to_is_a_mismatch() {
        // The vulnerability in one test: an attacker who can set a field would
        // otherwise be an attacker who can choose a tenant.
        let mut crossing = exchange("msg-1");
        crossing.tenant_claim = Some("tenant-b".to_owned());
        let assessment = assess(&crossing, Some(&peer("planner")), &policy());
        assert_eq!(assessment.claim_matches_policy, Some(false));
        assert_eq!(assessment.policy_tenant.as_deref(), Some("tenant-a"));
    }

    #[test]
    fn reachability_is_asked_about_the_policy_tenant_and_never_the_claim() {
        // Asking about the claim would let the claim answer its own question.
        let mut crossing = exchange("msg-1");
        crossing.tenant_claim = Some("tenant-b".to_owned());
        let assessment = assess(&crossing, Some(&peer("planner")), &policy());
        // tenant-a is what policy says, and tenant-a may reach planner.
        assert_eq!(assessment.tenant_may_reach_peer, Some(true));
        // The mismatch is still reported.
        assert_eq!(assessment.claim_matches_policy, Some(false));
    }

    #[test]
    fn a_subject_the_policy_does_not_know_leaves_the_question_open() {
        // Not "belongs to the tenant they claimed". A gap is a gap.
        let mut unknown = peer("planner");
        unknown.delegated_subject = Some("user-mallory".to_owned());
        let assessment = assess(&exchange("msg-1"), Some(&unknown), &policy());
        assert_eq!(assessment.policy_tenant, None);
        assert_eq!(assessment.claim_matches_policy, None);
        assert!(!assessment.is_decidable());
    }

    #[test]
    fn a_message_with_no_tenant_claim_is_undecidable_rather_than_compliant() {
        let mut untagged = exchange("msg-1");
        untagged.tenant_claim = None;
        let assessment = assess(&untagged, Some(&peer("planner")), &policy());
        assert_eq!(assessment.claim_matches_policy, None);
    }

    #[test]
    fn the_assessment_records_both_sides_so_a_finding_can_name_them() {
        let mut crossing = exchange("msg-1");
        crossing.tenant_claim = Some("tenant-b".to_owned());
        let assessment = assess(&crossing, Some(&peer("planner")), &policy());
        assert_eq!(assessment.claimed_tenant.as_deref(), Some("tenant-b"));
        assert_eq!(assessment.policy_tenant.as_deref(), Some("tenant-a"));
    }
}
