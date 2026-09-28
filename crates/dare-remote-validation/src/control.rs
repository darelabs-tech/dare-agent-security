//! Rate limit, budget and kill switch (BLUEPRINT §4.8, AD-06, AD-07).

use std::time::Duration;

use dare_adversarial::budget_enforce::BudgetState;
use dare_adversarial::{ExecutionBudget, ExpectedDecision, KillTrigger, ProofClass, VectorStep};
use tokio::time::Instant;

use crate::error::{RemoteError, Result};
use crate::limits::EffectiveLimits;

/// Minimum spacing between requests: `1000 ms / max_rps`. No bursts, no
/// tokens, no retries.
#[derive(Debug)]
pub struct RateLimiter {
    interval: Duration,
    next: Option<Instant>,
}

impl RateLimiter {
    pub fn new(max_rps: u32) -> RateLimiter {
        RateLimiter {
            interval: Duration::from_millis(1_000 / u64::from(max_rps.max(1))),
            next: None,
        }
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// When the next request may be sent (now, for the first).
    pub fn next_slot(&self) -> Instant {
        self.next.unwrap_or_else(Instant::now)
    }

    /// Wait for the next slot, unless it falls at or after `deadline`.
    pub async fn wait(&mut self, deadline: Instant) -> Result<()> {
        let slot = self.next_slot();
        if slot >= deadline {
            return Err(RemoteError::BudgetExhausted("duration"));
        }
        tokio::time::sleep_until(slot).await;
        self.next = Some(Instant::now() + self.interval);
        Ok(())
    }
}

/// The Cycle 009 budget, derived from the effective limits.
pub fn execution_budget(limits: &EffectiveLimits) -> ExecutionBudget {
    let requests = u64::from(limits.max_requests);
    ExecutionBudget {
        schema_version: "1".to_owned(),
        id: "remote-validation-run".to_owned(),
        max_operations: limits.max_requests,
        max_duration_seconds: limits.max_duration_s,
        max_state_changes: 0,
        max_bytes_read: requests.saturating_mul(limits.max_response_bytes),
        max_bytes_written: requests.saturating_mul(limits.max_request_bytes),
        max_external_egress_bytes: requests.saturating_mul(limits.max_request_bytes),
        max_retries: 0,
        max_chain_depth: limits.max_requests,
    }
}

/// One request as a Cycle 009 step: it writes `request_bytes` to the target
/// and changes nothing.
pub fn request_step(method: &str, protocol: &str, request_bytes: u64) -> VectorStep {
    VectorStep {
        method: method.to_owned(),
        capability: protocol.to_owned(),
        arguments: serde_json::Value::Null,
        safety_class: ProofClass::ReadOnly,
        synthetic_observation: ExpectedDecision::Inconclusive,
        bytes_read: 0,
        bytes_written: request_bytes,
        state_changes: 0,
        external_egress_bytes: request_bytes,
        retries: 0,
        target_id: None,
        identity_id: None,
        trigger: None,
    }
}

/// Budget over `BudgetState`: check before sending, consume after.
pub struct RemoteBudget {
    budget: ExecutionBudget,
    state: BudgetState,
}

impl RemoteBudget {
    pub fn new(limits: &EffectiveLimits) -> RemoteBudget {
        RemoteBudget {
            budget: execution_budget(limits),
            state: BudgetState::default(),
        }
    }

    pub fn check(&self, step: &VectorStep) -> Result<()> {
        // `check_next` is authoritative; the reason is named from the snapshot
        // because the Cycle 009 message is deliberately generic.
        if self.state.check_next(step, &self.budget).is_ok() {
            return Ok(());
        }
        let snapshot = &self.state.snapshot;
        Err(RemoteError::BudgetExhausted(
            if snapshot.operations >= self.budget.max_operations {
                "requests"
            } else if snapshot
                .external_egress_bytes
                .saturating_add(step.external_egress_bytes)
                > self.budget.max_external_egress_bytes
                || snapshot.bytes_written.saturating_add(step.bytes_written)
                    > self.budget.max_bytes_written
            {
                "bytes"
            } else {
                "duration"
            },
        ))
    }

    pub fn consume(&mut self, step: &VectorStep, bytes_read: u64) {
        let mut charged = step.clone();
        charged.bytes_read = bytes_read;
        self.state.consume(&charged);
    }

    pub fn requests(&self) -> u32 {
        self.state.snapshot.operations
    }
}

/// The remote kill switch. Once triggered it stays triggered, and the next
/// send is refused before any byte leaves.
#[derive(Debug, Default)]
pub struct RemoteKillSwitch {
    triggered: Option<KillTrigger>,
    consecutive_unstable: u32,
}

impl RemoteKillSwitch {
    pub fn check(&self) -> Result<()> {
        match self.triggered {
            Some(trigger) => Err(RemoteError::Killed(trigger)),
            None => Ok(()),
        }
    }

    pub fn triggered(&self) -> Option<KillTrigger> {
        self.triggered
    }

    pub fn trigger(&mut self, trigger: KillTrigger) {
        self.triggered.get_or_insert(trigger);
    }

    /// Record one response status. `429` and `5xx` are instability: the
    /// third in a row triggers the switch, or the first when the plan stops on
    /// its first failure.
    pub fn observe_status(&mut self, status: u16, stop_on_first_fail: bool) {
        if status == 429 || (500..600).contains(&status) {
            self.consecutive_unstable += 1;
            if stop_on_first_fail || self.consecutive_unstable >= 3 {
                self.trigger(KillTrigger::TargetInstability);
            }
        } else {
            self.consecutive_unstable = 0;
        }
        if (300..400).contains(&status) {
            // Redirects are never followed; that the target tried is enough.
            self.trigger(KillTrigger::UnexpectedTarget);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;

    #[tokio::test(start_paused = true)]
    async fn spacing_is_exactly_the_interval() {
        let mut limiter = RateLimiter::new(2);
        assert_eq!(limiter.interval(), Duration::from_millis(500));
        let start = Instant::now();
        let deadline = start + Duration::from_secs(60);
        let mut sent = Vec::new();
        for _ in 0..4 {
            limiter.wait(deadline).await.unwrap();
            sent.push(Instant::now() - start);
        }
        assert_eq!(sent, [0, 500, 1000, 1500].map(Duration::from_millis));
    }

    #[tokio::test(start_paused = true)]
    async fn a_slot_past_the_deadline_is_refused_without_sleeping() {
        let mut limiter = RateLimiter::new(1);
        let start = Instant::now();
        limiter
            .wait(start + Duration::from_millis(1_500))
            .await
            .unwrap();
        limiter
            .wait(start + Duration::from_millis(1_500))
            .await
            .unwrap();
        let before = Instant::now();
        assert!(matches!(
            limiter.wait(start + Duration::from_millis(1_500)).await,
            Err(RemoteError::BudgetExhausted("duration"))
        ));
        assert_eq!(Instant::now(), before, "did not sleep");
    }

    #[test]
    fn the_budget_is_derived_from_the_limits() {
        let limits = Limits {
            max_requests: Some(3),
            max_request_bytes: Some(100),
            ..Default::default()
        }
        .resolve()
        .unwrap();
        let budget = execution_budget(&limits);
        assert_eq!(
            (
                budget.max_operations,
                budget.max_state_changes,
                budget.max_retries
            ),
            (3, 0, 0)
        );
        assert_eq!(budget.max_external_egress_bytes, 300);
    }

    #[test]
    fn the_request_after_the_last_allowed_one_is_refused() {
        let limits = Limits {
            max_requests: Some(2),
            ..Default::default()
        }
        .resolve()
        .unwrap();
        let mut budget = RemoteBudget::new(&limits);
        let step = request_step("DARE_CONVERSATION_TURN", "DARE_CONVERSATION", 10);
        for _ in 0..2 {
            budget.check(&step).unwrap();
            budget.consume(&step, 5);
        }
        assert!(matches!(
            budget.check(&step),
            Err(RemoteError::BudgetExhausted(_))
        ));
        assert_eq!(budget.requests(), 2);
    }

    #[test]
    fn a_step_never_declares_a_state_change() {
        let step = request_step("A2A_MESSAGE_SEND", "A2A", 42);
        assert_eq!(
            (step.state_changes, step.retries, step.external_egress_bytes),
            (0, 0, 42)
        );
    }

    #[test]
    fn kill_triggers_latch_and_block_the_next_send() {
        let mut kill = RemoteKillSwitch::default();
        kill.check().unwrap();
        kill.trigger(KillTrigger::SecretDetected);
        kill.trigger(KillTrigger::OperatorStop);
        assert!(
            matches!(
                kill.check(),
                Err(RemoteError::Killed(KillTrigger::SecretDetected))
            ),
            "the first trigger is kept"
        );
    }

    #[test]
    fn instability_triggers_after_three_or_on_first_fail() {
        let mut kill = RemoteKillSwitch::default();
        kill.observe_status(503, false);
        kill.observe_status(200, false);
        kill.observe_status(429, false);
        kill.observe_status(500, false);
        assert!(kill.check().is_ok(), "the 200 reset the run of failures");
        kill.observe_status(502, false);
        assert_eq!(kill.triggered(), Some(KillTrigger::TargetInstability));
        let mut strict = RemoteKillSwitch::default();
        strict.observe_status(429, true);
        assert_eq!(strict.triggered(), Some(KillTrigger::TargetInstability));
    }

    #[test]
    fn a_redirect_status_triggers_unexpected_target() {
        let mut kill = RemoteKillSwitch::default();
        kill.observe_status(302, false);
        assert_eq!(kill.triggered(), Some(KillTrigger::UnexpectedTarget));
    }
}
