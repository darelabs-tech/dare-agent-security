//! The extension trust boundary.
//!
//! ```text
//! extension declaration != extension authority
//! ```
//!
//! An extension declares what it does. That declaration is written by the
//! extension, so it decides how carefully the thing must be approved — never
//! whether it is approved.
//!
//! # Failing closed, and why it is not paranoia
//!
//! A **required** extension nobody locally approved is the case that must fail
//! closed. Proceeding would mean speaking a protocol whose meaning this side
//! does not know, while the peer believes both sides agreed on it. Every
//! subsequent check would then be evaluating a message whose semantics are
//! partly unread — and passing that is worse than refusing it, because it looks
//! like a clean result.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::agent_card::AgentCard;
use crate::policy::A2aPolicy;

/// What the evidence says about one extension in use.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionAssessment {
    pub extension_id: String,
    /// Whether the card declared it.
    pub declared: bool,
    /// Whether the card marks it required.
    pub required: bool,
    /// Whether it claims to affect authorization or identity.
    pub claims_authority: bool,
    /// Whether local policy approved it at all.
    pub approved: bool,
    /// Whether local policy approved it to bear authority.
    pub authority_approved: bool,
}

impl ExtensionAssessment {
    /// Whether this extension can be interpreted safely.
    ///
    /// An undeclared extension in use, an unapproved one, or one claiming
    /// authority it was never granted are all cases where proceeding means
    /// guessing.
    pub fn is_safe_to_interpret(&self) -> bool {
        self.declared && self.approved && (!self.claims_authority || self.authority_approved)
    }

    /// Whether refusing is the only safe answer.
    ///
    /// A required extension that cannot be interpreted safely: the peer
    /// believes both sides agreed on semantics this side does not have.
    pub fn must_fail_closed(&self) -> bool {
        self.required && !self.is_safe_to_interpret()
    }
}

/// Assess every extension used or declared.
pub fn assess(
    card: Option<&AgentCard>,
    used: &BTreeSet<String>,
    policy: &A2aPolicy,
) -> Vec<ExtensionAssessment> {
    let mut assessments = Vec::new();
    let mut seen = BTreeSet::new();

    // Everything the card declares, whether or not it was used: a required
    // extension that was never used is still a requirement this side must be
    // able to meet.
    if let Some(card) = card {
        for extension in &card.extensions {
            seen.insert(extension.extension_id.clone());
            assessments.push(ExtensionAssessment {
                extension_id: extension.extension_id.clone(),
                declared: true,
                required: extension.required,
                claims_authority: extension.claims_authority,
                approved: policy
                    .extension_policy
                    .approved_extensions
                    .contains(&extension.extension_id),
                authority_approved: policy
                    .extension_policy
                    .authority_bearing_extensions
                    .contains(&extension.extension_id),
            });
        }
    }

    // Anything used but never declared. Using an extension the card never
    // mentioned is the peer speaking something it did not advertise.
    for extension_id in used {
        if seen.contains(extension_id) {
            continue;
        }
        assessments.push(ExtensionAssessment {
            extension_id: extension_id.clone(),
            declared: false,
            required: false,
            claims_authority: false,
            approved: policy
                .extension_policy
                .approved_extensions
                .contains(extension_id),
            authority_approved: policy
                .extension_policy
                .authority_bearing_extensions
                .contains(extension_id),
        });
    }

    assessments.sort();
    assessments
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_card::tests::card;
    use crate::agent_card::CardExtension;
    use crate::policy::tests::policy;

    fn card_with(extension: CardExtension) -> AgentCard {
        let mut card = card("card-1");
        card.extensions = vec![extension];
        card
    }

    #[test]
    fn a_declared_and_approved_extension_is_safe_to_interpret() {
        let card = card_with(CardExtension {
            extension_id: "ext-trace".to_owned(),
            required: false,
            claims_authority: false,
        });
        let assessments = assess(Some(&card), &BTreeSet::new(), &policy());
        assert_eq!(assessments.len(), 1);
        assert!(assessments[0].is_safe_to_interpret());
        assert!(!assessments[0].must_fail_closed());
    }

    #[test]
    fn an_unapproved_extension_is_not_safe_to_interpret() {
        let card = card_with(CardExtension {
            extension_id: "ext-unknown".to_owned(),
            required: false,
            claims_authority: false,
        });
        let assessments = assess(Some(&card), &BTreeSet::new(), &policy());
        assert!(!assessments[0].approved);
        assert!(!assessments[0].is_safe_to_interpret());
    }

    #[test]
    fn a_required_unapproved_extension_must_fail_closed() {
        // Proceeding would mean speaking a protocol whose meaning this side
        // does not know, while the peer believes both sides agreed on it.
        let card = card_with(CardExtension {
            extension_id: "ext-unknown".to_owned(),
            required: true,
            claims_authority: false,
        });
        let assessments = assess(Some(&card), &BTreeSet::new(), &policy());
        assert!(assessments[0].must_fail_closed());
    }

    #[test]
    fn an_extension_claiming_authority_needs_the_narrower_approval() {
        // Approving something to run is not approving it to decide.
        let card = card_with(CardExtension {
            extension_id: "ext-trace".to_owned(),
            required: false,
            claims_authority: true,
        });
        let assessments = assess(Some(&card), &BTreeSet::new(), &policy());
        assert!(assessments[0].approved);
        assert!(!assessments[0].authority_approved);
        assert!(!assessments[0].is_safe_to_interpret());
    }

    #[test]
    fn an_extension_used_but_never_declared_is_recorded() {
        // The peer speaking something it did not advertise.
        let card = card("card-1");
        let used = BTreeSet::from(["ext-surprise".to_owned()]);
        let assessments = assess(Some(&card), &used, &policy());
        let surprise = assessments
            .iter()
            .find(|assessment| assessment.extension_id == "ext-surprise")
            .expect("the undeclared extension");
        assert!(!surprise.declared);
        assert!(!surprise.is_safe_to_interpret());
    }

    #[test]
    fn a_required_extension_that_was_never_used_is_still_assessed() {
        // A requirement this side must be able to meet, whether or not this
        // particular exchange exercised it.
        let card = card_with(CardExtension {
            extension_id: "ext-required".to_owned(),
            required: true,
            claims_authority: false,
        });
        let assessments = assess(Some(&card), &BTreeSet::new(), &policy());
        assert_eq!(assessments.len(), 1);
        assert!(assessments[0].required);
    }

    #[test]
    fn a_run_with_no_card_and_no_extensions_assesses_nothing() {
        assert!(assess(None, &BTreeSet::new(), &policy()).is_empty());
    }

    #[test]
    fn the_assessment_order_is_deterministic() {
        let card = card("card-1");
        let used = BTreeSet::from(["ext-b".to_owned(), "ext-a".to_owned()]);
        let first = assess(Some(&card), &used, &policy());
        let second = assess(Some(&card), &used, &policy());
        assert_eq!(first, second);
    }
}
