use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::{
    model::{ExecutionBudget, VectorStep},
    AdversarialError, Result,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSnapshot {
    pub operations: u32,
    pub state_changes: u32,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub external_egress_bytes: u64,
    pub retries: u32,
    pub chain_depth: u32,
}

#[derive(Debug, Clone)]
pub struct BudgetState {
    pub snapshot: BudgetSnapshot,
    started: Instant,
}

impl Default for BudgetState {
    fn default() -> Self {
        Self {
            snapshot: BudgetSnapshot {
                operations: 0,
                state_changes: 0,
                bytes_read: 0,
                bytes_written: 0,
                external_egress_bytes: 0,
                retries: 0,
                chain_depth: 0,
            },
            started: Instant::now(),
        }
    }
}

impl BudgetState {
    pub fn check_next(&self, step: &VectorStep, budget: &ExecutionBudget) -> Result<()> {
        let exceeded = self.snapshot.operations.saturating_add(1) > budget.max_operations
            || self
                .snapshot
                .state_changes
                .saturating_add(step.state_changes)
                > budget.max_state_changes
            || self.snapshot.bytes_read.saturating_add(step.bytes_read) > budget.max_bytes_read
            || self
                .snapshot
                .bytes_written
                .saturating_add(step.bytes_written)
                > budget.max_bytes_written
            || self
                .snapshot
                .external_egress_bytes
                .saturating_add(step.external_egress_bytes)
                > budget.max_external_egress_bytes
            || self.snapshot.retries.saturating_add(step.retries) > budget.max_retries
            || self.snapshot.chain_depth.saturating_add(1) > budget.max_chain_depth
            || self.started.elapsed().as_secs() >= budget.max_duration_seconds;
        if exceeded {
            return Err(AdversarialError::BudgetExhausted(
                "next approved operation exceeds a fixed bound".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn consume(&mut self, step: &VectorStep) {
        self.snapshot.operations = self.snapshot.operations.saturating_add(1);
        self.snapshot.state_changes = self
            .snapshot
            .state_changes
            .saturating_add(step.state_changes);
        self.snapshot.bytes_read = self.snapshot.bytes_read.saturating_add(step.bytes_read);
        self.snapshot.bytes_written = self
            .snapshot
            .bytes_written
            .saturating_add(step.bytes_written);
        self.snapshot.external_egress_bytes = self
            .snapshot
            .external_egress_bytes
            .saturating_add(step.external_egress_bytes);
        self.snapshot.retries = self.snapshot.retries.saturating_add(step.retries);
        self.snapshot.chain_depth = self.snapshot.chain_depth.saturating_add(1);
    }
}
