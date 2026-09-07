//! Insufficient-scope challenge and bounded step-up.
//!
//! A step-up is supposed to *add* privilege. The failure this module exists to
//! catch is a retry that quietly drops something: the client was already
//! required to hold `invoices.read`, the server challenged for
//! `invoices.approve`, and the retry asked for `invoices.approve` alone. The
//! flow looks like a successful step-up and the client ends up holding less
//! than it started with, on a request that needed both.
//!
//! The required relationship is a union:
//!
//! ```text
//! retried_scopes ⊇ initial_required_scopes ∪ challenge_required_scopes
//! ```
//!
//! Retries are hard bounded. A client that retries on every challenge is
//! grinding the authorization server until something is granted, and an engine
//! with a generous ceiling would follow it there and call the result evidence.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{McpAuthSecurityError, Result};

/// Recorded scope challenge and step-up evidence.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeContext {
    /// Scopes the original request was required to hold.
    #[serde(default)]
    pub initial_required: Vec<String>,
    /// Scopes the challenge said were additionally required.
    #[serde(default)]
    pub challenge_required: Vec<String>,
    /// Scopes the retry actually requested.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retried: Vec<String>,
    /// Scopes the resulting token carried.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub granted: Vec<String>,
    /// How many step-up retries occurred.
    #[serde(default)]
    pub retry_count: u32,
    /// Whether a challenge was observed at all.
    #[serde(default)]
    pub challenge_observed: bool,
}

impl ScopeContext {
    pub fn validate(&self) -> Result<()> {
        for (list, label) in [
            (&self.initial_required, "initial required scope"),
            (&self.challenge_required, "challenged scope"),
            (&self.retried, "retried scope"),
            (&self.granted, "granted scope"),
        ] {
            if list.len() as u32 > crate::limits::HARD_MAX_SCOPES_PER_CONTEXT {
                return Err(McpAuthSecurityError::BudgetExhausted(format!(
                    "scope context declares too many entries for {label}"
                )));
            }
            for scope in list {
                crate::canonical::assert_safe_identifier(scope, label)?;
            }
        }
        if self.retry_count > crate::limits::HARD_MAX_SCOPE_STEP_UP_RETRIES {
            return Err(McpAuthSecurityError::BudgetExhausted(format!(
                "scope step-up retried {} times; the hard maximum is {}",
                self.retry_count,
                crate::limits::HARD_MAX_SCOPE_STEP_UP_RETRIES
            )));
        }
        Ok(())
    }

    /// The union a retry must cover.
    pub fn required_union(&self) -> BTreeSet<&str> {
        self.initial_required
            .iter()
            .chain(self.challenge_required.iter())
            .map(String::as_str)
            .collect()
    }

    /// Scopes the required union names that the retry dropped.
    ///
    /// Returned as a set rather than a boolean so a finding can say which
    /// scope went missing. "Step-up dropped a scope" is not actionable; "the
    /// retry dropped `invoices.read`" is.
    pub fn dropped_scopes(&self) -> Option<BTreeSet<&str>> {
        if !self.challenge_observed || self.retried.is_empty() {
            return None;
        }
        let retried: BTreeSet<&str> = self.retried.iter().map(String::as_str).collect();
        Some(
            self.required_union()
                .into_iter()
                .filter(|scope| !retried.contains(scope))
                .collect(),
        )
    }

    /// Whether the step-up preserved everything it had to.
    ///
    /// `None` when no challenge was observed or no retry followed one — there
    /// is nothing to judge, and treating that as agreement would let a flow
    /// that never stepped up report a clean step-up.
    pub fn step_up_holds(&self) -> Option<bool> {
        self.dropped_scopes().map(|dropped| dropped.is_empty())
    }

    /// Whether the retry count stayed inside the approved ceiling.
    pub fn retries_within_bound(&self) -> bool {
        self.retry_count <= crate::limits::HARD_MAX_SCOPE_STEP_UP_RETRIES
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn scope_context() -> ScopeContext {
        ScopeContext {
            initial_required: vec!["invoices.read".to_owned()],
            challenge_required: vec!["invoices.approve".to_owned()],
            retried: vec!["invoices.read".to_owned(), "invoices.approve".to_owned()],
            granted: vec!["invoices.read".to_owned(), "invoices.approve".to_owned()],
            retry_count: 1,
            challenge_observed: true,
        }
    }

    #[test]
    fn a_step_up_that_widens_holds() {
        let context = scope_context();
        context.validate().expect("valid");
        assert_eq!(context.step_up_holds(), Some(true));
        assert!(context.retries_within_bound());
    }

    #[test]
    fn a_retry_that_drops_a_previously_required_scope_fails() {
        // The failure the module exists for. The flow looks like a successful
        // step-up and the client ends up holding less than it started with.
        let mut context = scope_context();
        context.retried = vec!["invoices.approve".to_owned()];
        assert_eq!(context.step_up_holds(), Some(false));
        let dropped = context.dropped_scopes().expect("computed");
        assert_eq!(dropped.into_iter().collect::<Vec<_>>(), ["invoices.read"]);
    }

    #[test]
    fn a_dropped_scope_is_named_rather_than_merely_counted() {
        // "Step-up dropped a scope" is not actionable. Naming it is.
        let mut context = scope_context();
        context.initial_required = vec!["invoices.read".to_owned(), "invoices.list".to_owned()];
        context.retried = vec!["invoices.approve".to_owned(), "invoices.list".to_owned()];
        let dropped = context.dropped_scopes().expect("computed");
        assert_eq!(dropped.into_iter().collect::<Vec<_>>(), ["invoices.read"]);
    }

    #[test]
    fn a_retry_that_ignores_the_challenge_also_fails() {
        let mut context = scope_context();
        context.retried = vec!["invoices.read".to_owned()];
        assert_eq!(context.step_up_holds(), Some(false));
        let dropped = context.dropped_scopes().expect("computed");
        assert!(dropped.contains("invoices.approve"));
    }

    #[test]
    fn a_flow_with_no_challenge_answers_nothing() {
        // Treating this as agreement would let a flow that never stepped up
        // report a clean step-up.
        let mut context = scope_context();
        context.challenge_observed = false;
        assert_eq!(context.step_up_holds(), None);
    }

    #[test]
    fn a_challenge_with_no_retry_answers_nothing() {
        let mut context = scope_context();
        context.retried = vec![];
        assert_eq!(context.step_up_holds(), None);
    }

    #[test]
    fn exceeding_the_retry_ceiling_is_refused_rather_than_clamped() {
        let mut context = scope_context();
        context.retry_count = crate::limits::HARD_MAX_SCOPE_STEP_UP_RETRIES + 1;
        assert!(!context.retries_within_bound());
        assert!(matches!(
            context.validate().expect_err("refused"),
            McpAuthSecurityError::BudgetExhausted(_)
        ));
    }

    #[test]
    fn the_ceiling_itself_is_still_allowed() {
        let mut context = scope_context();
        context.retry_count = crate::limits::HARD_MAX_SCOPE_STEP_UP_RETRIES;
        context.validate().expect("the bound itself is allowed");
        assert!(context.retries_within_bound());
    }

    #[test]
    fn a_widened_retry_may_hold_more_than_required() {
        // Asking for more than the union is not a violation; only dropping is.
        let mut context = scope_context();
        context.retried.push("invoices.export".to_owned());
        assert_eq!(context.step_up_holds(), Some(true));
    }
}
