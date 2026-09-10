//! Skill authorization: the question authentication does not answer.
//!
//! ```text
//! successful authentication != skill authorization
//! ```
//!
//! Two different questions with two different answers. A peer can authenticate
//! perfectly and be asking for something the subject behind it may not have,
//! and a deployment that treats the first as the second has an authorization
//! model with exactly one rule: whoever gets in may do anything.
//!
//! # The boundary with Cycle 014
//!
//! Cycle 014 owns whether a **local tool** may run. This module answers whether
//! a **remote skill** may be invoked by a given subject. They look alike and are
//! not: a tool executes here under local authority, a skill executes there
//! under whatever the peer decides, and this engine never claims to have
//! decided the second half.

use serde::{Deserialize, Serialize};

use crate::message::Exchange;
use crate::peer::PeerIdentity;
use crate::policy::A2aPolicy;

/// What local policy says about one skill invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillAuthorizationAssessment {
    pub message_id: String,
    pub peer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_id: Option<String>,
    /// The subject a decision would be about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Whether policy allows it. `None` when no grant covers this peer and
    /// skill at all, which is a gap rather than a denial.
    pub allowed: Option<bool>,
    /// Whether the card even advertises the skill.
    pub skill_advertised: Option<bool>,
}

impl SkillAuthorizationAssessment {
    /// Whether there was enough on both sides to decide.
    pub fn is_decidable(&self) -> bool {
        self.allowed.is_some() && self.subject.is_some()
    }
}

/// Assess one exchange's skill invocation.
pub fn assess(
    exchange: &Exchange,
    peer: Option<&PeerIdentity>,
    policy: &A2aPolicy,
    card_skills: Option<&std::collections::BTreeSet<String>>,
) -> SkillAuthorizationAssessment {
    let subject = peer.and_then(|peer| peer.authorization_subject().map(ToOwned::to_owned));
    let skill_id = exchange.requested_skill.clone();

    let allowed = match (&skill_id, &subject) {
        (Some(skill), Some(subject)) => policy.skill_allows(&exchange.peer_id, skill, subject),
        _ => None,
    };

    let skill_advertised = match (&skill_id, card_skills) {
        (Some(skill), Some(advertised)) => Some(advertised.contains(skill)),
        _ => None,
    };

    SkillAuthorizationAssessment {
        message_id: exchange.message_id.clone(),
        peer_id: exchange.peer_id.clone(),
        skill_id,
        subject,
        allowed,
        skill_advertised,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::tests::exchange;
    use crate::peer::tests::peer;
    use crate::policy::tests::policy;
    use std::collections::BTreeSet;

    fn advertised() -> BTreeSet<String> {
        BTreeSet::from(["summarize".to_owned()])
    }

    #[test]
    fn an_authorized_subject_invoking_a_granted_skill_is_allowed() {
        let assessment = assess(
            &exchange("msg-1"),
            Some(&peer("planner")),
            &policy(),
            Some(&advertised()),
        );
        assert_eq!(assessment.allowed, Some(true));
        assert_eq!(assessment.subject.as_deref(), Some("user-alice"));
        assert!(assessment.is_decidable());
    }

    #[test]
    fn authenticating_is_not_being_authorized() {
        // The whole point of the module. The peer authenticated; the subject
        // behind it has no grant for this skill.
        let mut unauthorized = peer("planner");
        unauthorized.delegated_subject = Some("user-mallory".to_owned());
        let assessment = assess(
            &exchange("msg-1"),
            Some(&unauthorized),
            &policy(),
            Some(&advertised()),
        );
        assert!(unauthorized.is_authenticated());
        assert_eq!(assessment.allowed, Some(false));
    }

    #[test]
    fn a_skill_with_no_grant_at_all_is_undecidable_rather_than_denied() {
        // An absent policy is the absence of a decision. Denying everything
        // would make every exchange a finding.
        let mut other = exchange("msg-1");
        other.requested_skill = Some("transfer-funds".to_owned());
        let assessment = assess(
            &other,
            Some(&peer("planner")),
            &policy(),
            Some(&advertised()),
        );
        assert_eq!(assessment.allowed, None);
        assert!(!assessment.is_decidable());
    }

    #[test]
    fn an_unauthenticated_peer_yields_no_subject_and_no_decision() {
        let mut anonymous = peer("planner");
        anonymous.delegated_subject = None;
        anonymous.authenticated_principal = None;
        let assessment = assess(
            &exchange("msg-1"),
            Some(&anonymous),
            &policy(),
            Some(&advertised()),
        );
        assert_eq!(assessment.subject, None);
        assert_eq!(assessment.allowed, None);
        assert!(!assessment.is_decidable());
    }

    #[test]
    fn a_skill_the_card_never_advertised_is_recorded_separately() {
        // Distinct from being unauthorized. Invoking something the peer never
        // said it had is a different fact from invoking something it has and
        // the subject may not use.
        let mut unknown = exchange("msg-1");
        unknown.requested_skill = Some("transfer-funds".to_owned());
        let assessment = assess(
            &unknown,
            Some(&peer("planner")),
            &policy(),
            Some(&advertised()),
        );
        assert_eq!(assessment.skill_advertised, Some(false));
    }

    #[test]
    fn the_assessment_says_nothing_about_local_tool_execution() {
        // Cycle 014's question. A remote skill is not a local tool.
        let assessment = assess(
            &exchange("msg-1"),
            Some(&peer("planner")),
            &policy(),
            Some(&advertised()),
        );
        let rendered = serde_json::to_string(&assessment)
            .expect("serializes")
            .to_lowercase();
        for absent in ["tool", "invoke_local", "execution"] {
            assert!(
                !rendered.contains(absent),
                "the assessment claims something about `{absent}`"
            );
        }
    }
}
