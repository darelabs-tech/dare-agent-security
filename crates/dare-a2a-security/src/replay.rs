//! The replay and idempotency boundary.
//!
//! ```text
//! message retry != safe replay
//! ```
//!
//! A retry is a transport event. A safe replay is a claim about the operation,
//! and the two are only the same for a read. Repeating a read costs time;
//! repeating a transfer is a second transfer.
//!
//! So a repeated state-changing exchange may only be treated as safe when
//! something **proves** it: an idempotency key, or a policy that names the
//! skill idempotent. Absent both, the answer is that nobody established it —
//! never that it is fine.

use serde::{Deserialize, Serialize};

use crate::message::Exchange;
use crate::policy::A2aPolicy;
use crate::source::OperationEffect;

/// What the evidence says about repeating one exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayAssessment {
    pub message_id: String,
    pub is_repeat: bool,
    pub operation_effect: OperationEffect,
    /// Whether the exchange carried an idempotency key.
    pub has_idempotency_key: bool,
    /// Whether policy names the skill idempotent.
    pub policy_declares_idempotent: Option<bool>,
    /// Whether repeating this was proven safe. `None` when the question does
    /// not arise (not a repeat, or a read).
    pub replay_is_safe: Option<bool>,
}

impl ReplayAssessment {
    /// Whether the question arose at all.
    pub fn is_applicable(&self) -> bool {
        self.is_repeat && self.operation_effect.requires_replay_evidence()
    }
}

/// Assess one exchange's replay safety.
pub fn assess(exchange: &Exchange, policy: &A2aPolicy) -> ReplayAssessment {
    let has_idempotency_key = exchange.idempotency_key.is_some();
    let policy_declares_idempotent = exchange
        .requested_skill
        .as_deref()
        .map(|skill| policy.replay_policy.idempotent_skills.contains(skill));

    let applicable = exchange.requires_replay_evidence();
    let replay_is_safe = if !applicable {
        None
    } else {
        // Proven safe requires positive evidence. Either the operation carried
        // an idempotency key, or the deployment declared this skill idempotent.
        // Absent both, nobody established it — and `Some(false)` says exactly
        // that rather than "it is unsafe", which is a claim nobody made.
        let proven = has_idempotency_key || policy_declares_idempotent.unwrap_or(false);
        Some(proven)
    };

    ReplayAssessment {
        message_id: exchange.message_id.clone(),
        is_repeat: exchange.is_repeat,
        operation_effect: exchange.operation_effect,
        has_idempotency_key,
        policy_declares_idempotent,
        replay_is_safe,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::tests::exchange;
    use crate::policy::tests::policy;

    fn repeated(effect: OperationEffect) -> Exchange {
        let mut exchange = exchange("msg-1");
        exchange.is_repeat = true;
        exchange.operation_effect = effect;
        exchange
    }

    #[test]
    fn a_first_send_raises_no_replay_question() {
        let assessment = assess(&exchange("msg-1"), &policy());
        assert!(!assessment.is_applicable());
        assert_eq!(assessment.replay_is_safe, None);
    }

    #[test]
    fn a_repeated_read_raises_no_replay_question() {
        // Repeating a read costs time. It is not a security event.
        let assessment = assess(&repeated(OperationEffect::ReadOnly), &policy());
        assert!(!assessment.is_applicable());
        assert_eq!(assessment.replay_is_safe, None);
    }

    #[test]
    fn a_repeated_state_change_with_an_idempotency_key_is_proven_safe() {
        let mut keyed = repeated(OperationEffect::NonIdempotentStateChange);
        keyed.idempotency_key = Some("idem-1".to_owned());
        let assessment = assess(&keyed, &policy());
        assert!(assessment.is_applicable());
        assert_eq!(assessment.replay_is_safe, Some(true));
    }

    #[test]
    fn a_repeated_state_change_with_no_evidence_is_not_proven_safe() {
        // The finding. Nobody established that repeating this is fine, and an
        // engine that assumed so would be assuming the thing worth checking.
        let mut unproven = repeated(OperationEffect::NonIdempotentStateChange);
        unproven.idempotency_key = None;
        unproven.requested_skill = Some("transfer-funds".to_owned());
        let assessment = assess(&unproven, &policy());
        assert!(assessment.is_applicable());
        assert_eq!(assessment.replay_is_safe, Some(false));
        assert!(!assessment.has_idempotency_key);
        assert_eq!(assessment.policy_declares_idempotent, Some(false));
    }

    #[test]
    fn a_policy_declaring_the_skill_idempotent_is_positive_evidence() {
        // `summarize` is declared idempotent by the fixture policy.
        let assessment = assess(&repeated(OperationEffect::IdempotentStateChange), &policy());
        assert!(assessment.is_applicable());
        assert_eq!(assessment.policy_declares_idempotent, Some(true));
        assert_eq!(assessment.replay_is_safe, Some(true));
    }

    #[test]
    fn an_operation_claiming_idempotence_still_needs_someone_to_say_so() {
        // The claim is in the envelope, and the envelope is the sender's. What
        // counts is the deployment declaring it, or a key proving it.
        let mut claimed = repeated(OperationEffect::IdempotentStateChange);
        claimed.requested_skill = Some("transfer-funds".to_owned());
        claimed.idempotency_key = None;
        let assessment = assess(&claimed, &policy());
        assert_eq!(assessment.replay_is_safe, Some(false));
    }
}
