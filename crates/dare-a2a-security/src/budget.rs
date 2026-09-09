//! The admission ledger.
//!
//! Every bound is charged **before** the thing it bounds is persisted or
//! evaluated. That order is the whole point: a limit enforced after
//! normalization is a limit on reporting rather than on resource use, and an
//! oversized document that has already been parsed has already cost what the
//! bound existed to prevent.
//!
//! The ledger is also where the Cycle 019 post-merge correction lands. An
//! output artifact must account for **itself** in the run-wide budget, or the
//! budget bounds everything except the largest thing the run writes.

use serde::{Deserialize, Serialize};

use crate::error::{A2aSecurityError, Result};
use crate::limits;

/// What the ledger allowed, recorded so a report can show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSnapshot {
    pub input_bytes: usize,
    pub max_input_bytes: usize,
    pub peers_admitted: u32,
    pub max_peers: u32,
    pub exchanges_admitted: u32,
    pub max_exchanges: u32,
    pub output_bytes_used: usize,
    pub max_total_output_bytes: usize,
    pub output_bytes_per_trial: usize,
    pub trials_started: u32,
    pub state_changes: u32,
    pub external_egress_bytes: u64,
    pub exhausted: bool,
}

/// Charges every bound before the thing it bounds exists.
#[derive(Debug, Clone, Default)]
pub struct AdmissionLedger {
    input_bytes: usize,
    peers: u32,
    exchanges: u32,
    output_bytes: usize,
    trial_output_bytes: usize,
    trials_started: u32,
    exhausted: bool,
}

impl AdmissionLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Charge raw input bytes before a parser sees them.
    ///
    /// Called with the byte length, not the parsed value, because a document
    /// refused after parsing has already been parsed.
    pub fn admit_bytes(&mut self, len: usize, label: &str) -> Result<()> {
        if len > limits::HARD_MAX_DOCUMENT_BYTES {
            return self.exhaust(format!(
                "{label} is {len} bytes; the hard maximum for a single document is {}",
                limits::HARD_MAX_DOCUMENT_BYTES
            ));
        }
        self.input_bytes += len;
        Ok(())
    }

    pub fn admit_peer(&mut self) -> Result<()> {
        if self.peers + 1 > limits::HARD_MAX_PEERS {
            return self.exhaust(format!(
                "more peers than the hard maximum of {}",
                limits::HARD_MAX_PEERS
            ));
        }
        self.peers += 1;
        Ok(())
    }

    pub fn admit_exchange(&mut self) -> Result<()> {
        if self.exchanges + 1 > limits::HARD_MAX_EXCHANGES {
            return self.exhaust(format!(
                "more exchanges than the hard maximum of {}",
                limits::HARD_MAX_EXCHANGES
            ));
        }
        self.exchanges += 1;
        Ok(())
    }

    /// Charge bytes an artifact is about to occupy.
    ///
    /// Called *before* the write. The result artifact charges itself here too:
    /// the Cycle 019 post-merge review found that exempting it left the budget
    /// bounding everything except the largest thing the run produced.
    pub fn admit_output(&mut self, bytes: usize) -> Result<()> {
        if self.trial_output_bytes + bytes > limits::MAX_OUTPUT_BYTES_PER_TRIAL {
            return self.exhaust(format!(
                "one trial would retain more than {} bytes",
                limits::MAX_OUTPUT_BYTES_PER_TRIAL
            ));
        }
        if self.output_bytes + bytes > limits::MAX_TOTAL_OUTPUT_BYTES {
            return self.exhaust(format!(
                "the run would retain more than {} bytes in total",
                limits::MAX_TOTAL_OUTPUT_BYTES
            ));
        }
        self.trial_output_bytes += bytes;
        self.output_bytes += bytes;
        Ok(())
    }

    /// Begin a trial.
    ///
    /// Resets the per-trial output counter and **nothing else**. Run-wide
    /// totals that reset per trial would be a budget a caller could evade by
    /// asking for more trials.
    pub fn begin_trial(&mut self) -> Result<()> {
        if self.trials_started + 1 > limits::HARD_MAX_TRIALS {
            return self.exhaust(format!(
                "more trials than the hard maximum of {}",
                limits::HARD_MAX_TRIALS
            ));
        }
        self.trials_started += 1;
        self.trial_output_bytes = 0;
        Ok(())
    }

    /// Refuse a delegation chain deeper than the ceiling.
    pub fn assert_delegation_depth(&mut self, depth: u32) -> Result<()> {
        if depth > limits::HARD_MAX_DELEGATION_DEPTH {
            return self.exhaust(format!(
                "a delegation chain is {depth} hops deep; the hard maximum is {}",
                limits::HARD_MAX_DELEGATION_DEPTH
            ));
        }
        Ok(())
    }

    pub fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            input_bytes: self.input_bytes,
            max_input_bytes: limits::HARD_MAX_DOCUMENT_BYTES,
            peers_admitted: self.peers,
            max_peers: limits::HARD_MAX_PEERS,
            exchanges_admitted: self.exchanges,
            max_exchanges: limits::HARD_MAX_EXCHANGES,
            output_bytes_used: self.output_bytes,
            max_total_output_bytes: limits::MAX_TOTAL_OUTPUT_BYTES,
            output_bytes_per_trial: limits::MAX_OUTPUT_BYTES_PER_TRIAL,
            trials_started: self.trials_started,
            // Not counters this engine increments — assertions about what it
            // cannot do. Nothing in this crate can change product state or send
            // a byte, so these are constants and a test says so.
            state_changes: limits::MAX_STATE_CHANGES,
            external_egress_bytes: limits::EXTERNAL_EGRESS_BYTES,
            exhausted: self.exhausted,
        }
    }

    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Record exhaustion and refuse.
    ///
    /// The flag is never cleared: a run that hit a bound stays marked, so a
    /// later report cannot present a truncated evaluation as a complete one.
    fn exhaust(&mut self, reason: String) -> Result<()> {
        self.exhausted = true;
        Err(A2aSecurityError::BudgetExhausted(reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_oversized_document_is_refused_before_it_is_parsed() {
        let mut ledger = AdmissionLedger::new();
        let error = ledger
            .admit_bytes(limits::HARD_MAX_DOCUMENT_BYTES + 1, "an Agent Card")
            .expect_err("must be refused");
        assert!(matches!(error, A2aSecurityError::BudgetExhausted(_)));
        assert!(ledger.is_exhausted());
    }

    #[test]
    fn input_bytes_do_not_reset_between_documents() {
        // A caller that could reset the counter by supplying two documents
        // would have a budget in name only.
        let mut ledger = AdmissionLedger::new();
        ledger.admit_bytes(1_000, "a card").expect("admitted");
        ledger.admit_bytes(2_000, "a trace").expect("admitted");
        assert_eq!(ledger.snapshot().input_bytes, 3_000);
    }

    #[test]
    fn the_peer_and_exchange_ceilings_are_refused_rather_than_clamped() {
        // Clamping would silently evaluate a subset and report on it as though
        // it were the whole.
        let mut ledger = AdmissionLedger::new();
        for _ in 0..limits::HARD_MAX_PEERS {
            ledger.admit_peer().expect("admitted");
        }
        assert!(ledger.admit_peer().is_err());

        let mut ledger = AdmissionLedger::new();
        for _ in 0..limits::HARD_MAX_EXCHANGES {
            ledger.admit_exchange().expect("admitted");
        }
        assert!(ledger.admit_exchange().is_err());
    }

    #[test]
    fn run_wide_output_totals_do_not_reset_between_trials() {
        // Only the per-trial counter resets. A run-wide total that reset per
        // trial would be a budget a caller could evade by asking for more
        // trials.
        let mut ledger = AdmissionLedger::new();
        let per_trial = limits::MAX_OUTPUT_BYTES_PER_TRIAL;
        let trials = limits::MAX_TOTAL_OUTPUT_BYTES / per_trial;

        for _ in 0..trials {
            ledger.begin_trial().expect("trial starts");
            ledger.admit_output(per_trial).expect("admitted");
        }
        ledger.begin_trial().expect("trial starts");
        assert!(
            ledger.admit_output(1).is_err(),
            "the run-wide total reset between trials"
        );
    }

    #[test]
    fn the_per_trial_output_bound_is_enforced_as_well() {
        let mut ledger = AdmissionLedger::new();
        ledger.begin_trial().expect("trial starts");
        assert!(ledger
            .admit_output(limits::MAX_OUTPUT_BYTES_PER_TRIAL + 1)
            .is_err());
    }

    #[test]
    fn the_trial_ceiling_is_enforced() {
        let mut ledger = AdmissionLedger::new();
        for _ in 0..limits::HARD_MAX_TRIALS {
            ledger.begin_trial().expect("trial starts");
        }
        assert!(ledger.begin_trial().is_err());
    }

    #[test]
    fn a_deep_delegation_chain_is_refused() {
        // Each hop is an opportunity for authority to widen, and a chain nobody
        // can hold in their head is a chain nobody audits.
        let mut ledger = AdmissionLedger::new();
        ledger
            .assert_delegation_depth(limits::HARD_MAX_DELEGATION_DEPTH)
            .expect("at the ceiling");
        assert!(ledger
            .assert_delegation_depth(limits::HARD_MAX_DELEGATION_DEPTH + 1)
            .is_err());
    }

    #[test]
    fn a_snapshot_records_zero_state_changes_and_zero_egress() {
        let ledger = AdmissionLedger::new();
        let snapshot = ledger.snapshot();
        assert_eq!(snapshot.state_changes, 0);
        assert_eq!(snapshot.external_egress_bytes, 0);
    }

    #[test]
    fn exhaustion_is_recorded_and_never_cleared() {
        // A run that hit a bound stays marked, so a later report cannot present
        // a truncated evaluation as a complete one.
        let mut ledger = AdmissionLedger::new();
        assert!(!ledger.is_exhausted());
        let _ = ledger.admit_bytes(limits::HARD_MAX_DOCUMENT_BYTES + 1, "a card");
        assert!(ledger.is_exhausted());
        ledger.admit_bytes(1, "a small card").expect("admitted");
        assert!(ledger.is_exhausted(), "exhaustion was cleared");
    }

    #[test]
    fn a_refusal_names_the_bound_rather_than_the_content() {
        let mut ledger = AdmissionLedger::new();
        let error = ledger
            .admit_bytes(limits::HARD_MAX_DOCUMENT_BYTES + 1, "an Agent Card")
            .expect_err("refused");
        let message = error.to_string();
        assert!(message.contains("hard maximum"));
        assert!(message.contains("Agent Card"));
    }
}
