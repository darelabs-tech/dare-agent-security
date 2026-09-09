//! The data-scope boundary.
//!
//! Data labels travel with a message. Whether they may travel *to this
//! destination* is a policy question the protocol does not answer, and a
//! deployment that lets a label ride along without checking has disclosure
//! controls only as strong as whoever set the label.
//!
//! Two directions are checked, because widening happens in both:
//!
//! - **peer ceiling** — the most sensitive thing this peer may receive;
//! - **destination approval** — where onward disclosure may go.

use serde::{Deserialize, Serialize};

use crate::message::Exchange;
use crate::policy::A2aPolicy;
use crate::source::DataSensitivity;

/// What the evidence says about one exchange's data scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataScopeAssessment {
    pub message_id: String,
    pub peer_id: String,
    /// The most sensitive label the exchange carries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_sensitivity: Option<DataSensitivity>,
    /// The ceiling policy sets for this peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_ceiling: Option<DataSensitivity>,
    /// Whether the exchange stayed within the ceiling. `None` when either side
    /// is silent.
    pub within_ceiling: Option<bool>,
}

impl DataScopeAssessment {
    pub fn is_decidable(&self) -> bool {
        self.within_ceiling.is_some()
    }
}

/// Assess one exchange's data scope.
pub fn assess(exchange: &Exchange, policy: &A2aPolicy) -> DataScopeAssessment {
    let peak_sensitivity = exchange.peak_sensitivity();
    let peer_ceiling = policy.data_scope_policy.ceiling_for(&exchange.peer_id);

    let within_ceiling = match (peak_sensitivity, peer_ceiling) {
        (Some(peak), Some(ceiling)) => Some(peak <= ceiling),
        _ => None,
    };

    DataScopeAssessment {
        message_id: exchange.message_id.clone(),
        peer_id: exchange.peer_id.clone(),
        peak_sensitivity,
        peer_ceiling,
        within_ceiling,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::tests::exchange;
    use crate::policy::tests::policy;
    use std::collections::BTreeSet;

    #[test]
    fn an_exchange_within_the_ceiling_agrees() {
        let assessment = assess(&exchange("msg-1"), &policy());
        assert_eq!(assessment.peak_sensitivity, Some(DataSensitivity::Internal));
        assert_eq!(assessment.peer_ceiling, Some(DataSensitivity::Internal));
        assert_eq!(assessment.within_ceiling, Some(true));
    }

    #[test]
    fn an_exchange_above_the_ceiling_is_a_widening() {
        let mut widened = exchange("msg-1");
        widened.parts[0].data_labels = BTreeSet::from([DataSensitivity::Restricted]);
        let assessment = assess(&widened, &policy());
        assert_eq!(assessment.within_ceiling, Some(false));
        assert_eq!(
            assessment.peak_sensitivity,
            Some(DataSensitivity::Restricted)
        );
    }

    #[test]
    fn an_exchange_below_the_ceiling_is_not_a_finding() {
        // A peer receiving less than it is allowed has crossed no boundary, and
        // reporting it would train an operator to skim past the ones that
        // matter.
        let mut narrower = exchange("msg-1");
        narrower.parts[0].data_labels = BTreeSet::from([DataSensitivity::Public]);
        assert_eq!(assess(&narrower, &policy()).within_ceiling, Some(true));
    }

    #[test]
    fn a_peer_with_no_ceiling_leaves_the_question_open() {
        let mut unknown_peer = exchange("msg-1");
        unknown_peer.peer_id = "unlisted-peer".to_owned();
        let assessment = assess(&unknown_peer, &policy());
        assert_eq!(assessment.peer_ceiling, None);
        assert_eq!(assessment.within_ceiling, None);
        assert!(!assessment.is_decidable());
    }

    #[test]
    fn an_unlabelled_exchange_leaves_the_question_open() {
        // Absence of a label is not evidence of harmlessness. It is evidence
        // that nobody labelled it.
        let mut unlabelled = exchange("msg-1");
        unlabelled.parts[0].data_labels = BTreeSet::new();
        let assessment = assess(&unlabelled, &policy());
        assert_eq!(assessment.peak_sensitivity, None);
        assert_eq!(assessment.within_ceiling, None);
    }

    #[test]
    fn the_peak_label_decides_rather_than_the_first_one() {
        // A message carrying both public and restricted parts is a restricted
        // message.
        let mut mixed = exchange("msg-1");
        mixed.parts[0].data_labels =
            BTreeSet::from([DataSensitivity::Public, DataSensitivity::Restricted]);
        assert_eq!(
            assess(&mixed, &policy()).peak_sensitivity,
            Some(DataSensitivity::Restricted)
        );
    }
}
