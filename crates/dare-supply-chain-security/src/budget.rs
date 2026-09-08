//! The admission ledger.
//!
//! Every bound here is an **admission** boundary, not a metric. The distinction
//! is the whole module, and it is Cycle 018's most expensive lesson: that cycle
//! shipped a ledger that counted bytes it did not bound, so over-budget
//! material was normalized, evaluated and persisted while the artifact reported
//! a number under the ceiling. The count described a run that had not happened.
//!
//! So the order is frozen, and the code is arranged so that skipping a step is
//! awkward rather than merely discouraged:
//!
//! ```text
//! raw bytes
//!   → byte admission
//!   → parse / schema
//!   → component and relationship admission
//!   → normalization
//!   → persisted evidence admission
//!   → invariant evaluation
//! ```
//!
//! An object that was not charged is not normalized, not evaluated and not
//! written. And a run stopped by a bound before its evidence was complete
//! cannot report PASS — "we found no violation" and "we stopped looking" are
//! different statements, and only the first is a pass.

use serde::{Deserialize, Serialize};

use crate::error::{Result, SupplyChainError};
use crate::limits;

/// What a run is allowed to consume, and what it consumed.
///
/// Serialized into the result artifact so a reader can check the claim rather
/// than trust it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSnapshot {
    pub bom_bytes_admitted: usize,
    pub max_bom_bytes: usize,
    pub components_admitted: u32,
    pub max_components: u32,
    pub relationships_admitted: u32,
    pub max_relationships: u32,
    pub output_bytes_used: usize,
    pub max_total_output_bytes: usize,
    pub output_bytes_per_trial: usize,
    /// Always zero. Present so the artifact states it rather than omitting it.
    pub state_changes: u32,
    /// Always zero.
    pub external_egress_bytes: u64,
    /// Whether any bound was reached during the run.
    pub exhausted: bool,
}

/// Tracks admission across a whole run.
///
/// Run-wide totals never reset between components, documents or trials. A
/// counter that resets is not a bound, and a document split into ten parts
/// would otherwise pass ten times over.
#[derive(Debug, Clone)]
pub struct AdmissionLedger {
    bom_bytes: usize,
    components: u32,
    relationships: u32,
    output_bytes: usize,
    trial_output_bytes: usize,
    exhausted: bool,
}

impl Default for AdmissionLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl AdmissionLedger {
    pub fn new() -> Self {
        Self {
            bom_bytes: 0,
            components: 0,
            relationships: 0,
            output_bytes: 0,
            trial_output_bytes: 0,
            exhausted: false,
        }
    }

    /// Admit raw document bytes **before** anything parses them.
    ///
    /// First in the order for a reason: a 40 MB document that would be refused
    /// after parsing has already been parsed, and parsing is where a graph bomb
    /// does its work.
    pub fn admit_bytes(&mut self, len: usize, label: &str) -> Result<()> {
        if len > limits::HARD_MAX_BOM_BYTES {
            self.exhausted = true;
            return Err(SupplyChainError::BudgetExhausted(format!(
                "{label} is {len} bytes; the hard maximum is {}",
                limits::HARD_MAX_BOM_BYTES
            )));
        }
        if self.bom_bytes + len > limits::HARD_MAX_BOM_BYTES {
            self.exhausted = true;
            return Err(SupplyChainError::BudgetExhausted(format!(
                "admitting {label} would take the run past {} total input bytes",
                limits::HARD_MAX_BOM_BYTES
            )));
        }
        self.bom_bytes += len;
        Ok(())
    }

    /// Admit one component into the normalized model.
    pub fn admit_component(&mut self) -> Result<()> {
        if self.components + 1 > limits::HARD_MAX_COMPONENTS {
            self.exhausted = true;
            return Err(SupplyChainError::BudgetExhausted(format!(
                "the run admitted {} components; the hard maximum is {}",
                self.components,
                limits::HARD_MAX_COMPONENTS
            )));
        }
        self.components += 1;
        Ok(())
    }

    /// Admit one relationship edge into the graph.
    pub fn admit_relationship(&mut self) -> Result<()> {
        if self.relationships + 1 > limits::HARD_MAX_RELATIONSHIPS {
            self.exhausted = true;
            return Err(SupplyChainError::BudgetExhausted(format!(
                "the run admitted {} relationships; the hard maximum is {}",
                self.relationships,
                limits::HARD_MAX_RELATIONSHIPS
            )));
        }
        self.relationships += 1;
        Ok(())
    }

    /// Admit retained evidence bytes.
    ///
    /// Charged per trial and run-wide at once, because either ceiling alone
    /// leaves the other reachable.
    pub fn admit_output(&mut self, bytes: usize) -> Result<()> {
        if self.trial_output_bytes + bytes > limits::MAX_OUTPUT_BYTES_PER_TRIAL {
            self.exhausted = true;
            return Err(SupplyChainError::BudgetExhausted(format!(
                "this trial would retain more than {} bytes",
                limits::MAX_OUTPUT_BYTES_PER_TRIAL
            )));
        }
        if self.output_bytes + bytes > limits::MAX_TOTAL_OUTPUT_BYTES {
            self.exhausted = true;
            return Err(SupplyChainError::BudgetExhausted(format!(
                "the run would retain more than {} bytes in total",
                limits::MAX_TOTAL_OUTPUT_BYTES
            )));
        }
        self.trial_output_bytes += bytes;
        self.output_bytes += bytes;
        Ok(())
    }

    /// Begin a new trial's per-trial output accounting.
    ///
    /// Only the per-trial counter resets. The run-wide one deliberately does
    /// not: that is the difference between a bound and a rolling average.
    pub fn begin_trial(&mut self) {
        self.trial_output_bytes = 0;
    }

    /// Whether any bound was reached.
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Refuse a dependency walk that went deeper than the approved ceiling.
    pub fn assert_depth(&mut self, depth: u32) -> Result<()> {
        if depth > limits::HARD_MAX_DEPENDENCY_DEPTH {
            self.exhausted = true;
            return Err(SupplyChainError::BudgetExhausted(format!(
                "a dependency path reached depth {depth}; the hard maximum is {}",
                limits::HARD_MAX_DEPENDENCY_DEPTH
            )));
        }
        Ok(())
    }

    pub fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            bom_bytes_admitted: self.bom_bytes,
            max_bom_bytes: limits::HARD_MAX_BOM_BYTES,
            components_admitted: self.components,
            max_components: limits::HARD_MAX_COMPONENTS,
            relationships_admitted: self.relationships,
            max_relationships: limits::HARD_MAX_RELATIONSHIPS,
            output_bytes_used: self.output_bytes,
            max_total_output_bytes: limits::MAX_TOTAL_OUTPUT_BYTES,
            output_bytes_per_trial: limits::MAX_OUTPUT_BYTES_PER_TRIAL,
            state_changes: limits::MAX_STATE_CHANGES,
            external_egress_bytes: limits::EXTERNAL_EGRESS_BYTES,
            exhausted: self.exhausted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_oversized_document_is_refused_before_it_is_parsed() {
        // First in the order, and the reason is that parsing is where a graph
        // bomb does its work. Refusing after the parse is refusing too late.
        let mut ledger = AdmissionLedger::new();
        let err = ledger
            .admit_bytes(limits::HARD_MAX_BOM_BYTES + 1, "bom")
            .expect_err("must be refused");
        assert!(matches!(err, SupplyChainError::BudgetExhausted(_)));
        assert!(ledger.is_exhausted());
    }

    #[test]
    fn input_bytes_do_not_reset_between_documents() {
        // Otherwise a document split into ten parts passes ten times over.
        let mut ledger = AdmissionLedger::new();
        let half = limits::HARD_MAX_BOM_BYTES / 2;
        ledger.admit_bytes(half, "first").expect("fits");
        ledger.admit_bytes(half, "second").expect("fits");
        assert!(ledger.admit_bytes(1024, "third").is_err());
    }

    #[test]
    fn the_component_ceiling_is_refused_rather_than_clamped() {
        // Refused, not clamped. A clamped run proceeds as though it had asked
        // for something reasonable, and the operator never learns otherwise.
        let mut ledger = AdmissionLedger::new();
        for _ in 0..limits::HARD_MAX_COMPONENTS {
            ledger.admit_component().expect("within bounds");
        }
        assert!(ledger.admit_component().is_err());
        assert_eq!(
            ledger.snapshot().components_admitted,
            limits::HARD_MAX_COMPONENTS
        );
    }

    #[test]
    fn the_relationship_ceiling_is_enforced_too() {
        let mut ledger = AdmissionLedger::new();
        for _ in 0..limits::HARD_MAX_RELATIONSHIPS {
            ledger.admit_relationship().expect("within bounds");
        }
        assert!(ledger.admit_relationship().is_err());
    }

    #[test]
    fn run_wide_output_totals_do_not_reset_between_trials() {
        // Only the per-trial counter resets. A run-wide counter that reset with
        // it would be a rolling average wearing a bound's name.
        let mut ledger = AdmissionLedger::new();
        let per_trial = limits::MAX_OUTPUT_BYTES_PER_TRIAL;
        let trials = limits::MAX_TOTAL_OUTPUT_BYTES / per_trial;

        for _ in 0..trials {
            ledger.begin_trial();
            ledger
                .admit_output(per_trial)
                .expect("within the trial bound");
        }
        ledger.begin_trial();
        assert!(
            ledger.admit_output(1).is_err(),
            "the run-wide ceiling reset when a trial began"
        );
    }

    #[test]
    fn the_per_trial_output_bound_is_enforced_as_well() {
        let mut ledger = AdmissionLedger::new();
        ledger.begin_trial();
        assert!(ledger
            .admit_output(limits::MAX_OUTPUT_BYTES_PER_TRIAL + 1)
            .is_err());
    }

    #[test]
    fn a_deep_dependency_path_is_refused() {
        let mut ledger = AdmissionLedger::new();
        ledger
            .assert_depth(limits::HARD_MAX_DEPENDENCY_DEPTH)
            .expect("the ceiling itself is allowed");
        assert!(ledger
            .assert_depth(limits::HARD_MAX_DEPENDENCY_DEPTH + 1)
            .is_err());
    }

    #[test]
    fn a_snapshot_records_zero_state_changes_and_zero_egress() {
        let snapshot = AdmissionLedger::new().snapshot();
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
        assert!(!snapshot.exhausted);
    }

    #[test]
    fn exhaustion_is_recorded_and_never_cleared() {
        // A run that hit a bound and then carried on must still say so. An
        // exhaustion flag that could be cleared would let the artifact describe
        // a clean run that was not one.
        let mut ledger = AdmissionLedger::new();
        let _ = ledger.admit_bytes(limits::HARD_MAX_BOM_BYTES + 1, "bom");
        assert!(ledger.snapshot().exhausted);
        ledger.begin_trial();
        ledger.admit_component().expect("still usable");
        assert!(
            ledger.snapshot().exhausted,
            "beginning a trial cleared the exhaustion flag"
        );
    }

    #[test]
    fn a_refusal_names_the_bound_rather_than_the_content() {
        let mut ledger = AdmissionLedger::new();
        let err = ledger
            .admit_bytes(limits::HARD_MAX_BOM_BYTES + 1, "cyclonedx document")
            .expect_err("refused");
        let message = err.to_string();
        assert!(message.contains("hard maximum"));
        for verdict in ["PASS", "FAIL", "INCONCLUSIVE"] {
            assert!(!message.contains(verdict));
        }
    }
}
