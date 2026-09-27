//! The run-wide ledger: turns and output bytes, charged before they happen.
//!
//! Every persisted artifact is admitted before it is written, and the result
//! artifact is charged for its own bytes (Cycle 019 F05, Blueprint AD-07).
//! Evidence is charged as each turn is recorded, so a run cannot accumulate
//! more retained evidence than it could ever write.

use serde::{Deserialize, Serialize};

use crate::error::{MultiTurnError, Result};
use crate::limits::EffectiveBounds;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSnapshot {
    pub turns: u32,
    pub output_bytes: u64,
    /// Always zero: no mode can change target state.
    pub state_changes: u32,
    /// Always zero: no mode has a network path.
    pub egress_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct OutputLedger {
    bounds: EffectiveBounds,
    turns_total: u32,
    turns_in_conversation: u32,
    evidence_bytes: usize,
    output_bytes: usize,
}

impl OutputLedger {
    pub fn new(bounds: EffectiveBounds) -> Self {
        Self {
            bounds,
            turns_total: 0,
            turns_in_conversation: 0,
            evidence_bytes: 0,
            output_bytes: 0,
        }
    }

    pub fn begin_conversation(&mut self) {
        self.turns_in_conversation = 0;
    }

    /// Charge one turn. Refused once the per-conversation turn bound is reached.
    pub fn admit_turn(&mut self) -> Result<()> {
        if self.turns_in_conversation >= self.bounds.max_turns_per_conversation {
            return Err(MultiTurnError::OutputBudgetExceeded(
                "turn bound reached".into(),
            ));
        }
        self.turns_in_conversation += 1;
        self.turns_total += 1;
        Ok(())
    }

    /// Charge retained evidence against the same byte ceiling as output.
    pub fn admit_evidence(&mut self, bytes: usize) -> Result<()> {
        let next = self.evidence_bytes.saturating_add(bytes);
        if next > self.bounds.max_total_output_bytes {
            return Err(MultiTurnError::OutputBudgetExceeded(
                "retained evidence".into(),
            ));
        }
        self.evidence_bytes = next;
        Ok(())
    }

    /// Admit an artifact before writing it. Nothing is charged on refusal.
    pub fn admit_output(&mut self, bytes: usize) -> Result<()> {
        let next = self.output_bytes.saturating_add(bytes);
        if next > self.bounds.max_total_output_bytes {
            return Err(MultiTurnError::OutputBudgetExceeded(
                "artifact would exceed the output budget".into(),
            ));
        }
        self.output_bytes = next;
        Ok(())
    }

    pub fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            turns: self.turns_total,
            output_bytes: self.output_bytes as u64,
            state_changes: 0,
            egress_bytes: 0,
        }
    }

    pub fn remaining_output(&self) -> usize {
        self.bounds
            .max_total_output_bytes
            .saturating_sub(self.output_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger(turns: u32, bytes: usize) -> OutputLedger {
        OutputLedger::new(EffectiveBounds {
            max_turns_per_conversation: turns,
            max_total_output_bytes: bytes,
            ..EffectiveBounds::default()
        })
    }

    #[test]
    fn the_turn_bound_is_per_conversation_and_counted_in_total() {
        let mut l = ledger(2, 100);
        assert!(l.admit_turn().is_ok() && l.admit_turn().is_ok());
        assert!(l.admit_turn().is_err());
        l.begin_conversation();
        assert!(l.admit_turn().is_ok());
        assert_eq!(l.snapshot().turns, 3);
    }

    #[test]
    fn over_budget_output_is_refused_and_not_charged() {
        let mut l = ledger(1, 100);
        assert!(l.admit_output(60).is_ok());
        assert!(l.admit_output(41).is_err());
        assert_eq!(
            l.snapshot().output_bytes,
            60,
            "a refused artifact costs nothing"
        );
        assert!(l.admit_output(40).is_ok());
        assert_eq!(l.remaining_output(), 0);
    }

    #[test]
    fn evidence_is_bounded_by_the_same_ceiling() {
        let mut l = ledger(1, 10);
        assert!(l.admit_evidence(10).is_ok());
        assert!(l.admit_evidence(1).is_err());
    }

    #[test]
    fn the_snapshot_never_reports_state_change_or_egress() {
        let s = ledger(1, 1).snapshot();
        assert_eq!((s.state_changes, s.egress_bytes), (0, 0));
    }
}
