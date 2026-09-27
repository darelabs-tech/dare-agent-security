//! The adapter contract: the only place a target's responses come from.
//!
//! [`ConversationAdapter`] is the first adapter in this repository that sees
//! the conversation so far. Cycle 013's `HarnessAdapter::observe` is a pure
//! function of the trial index and stays that way; multi-turn state lives
//! here instead (Blueprint AD-04).
//!
//! An adapter has no network, filesystem-write or process capability. The
//! same instance serves every conversation of a scenario, which is exactly
//! what conversation isolation (I07) needs to test.

use crate::conversation::ConversationState;
use crate::graph::StrategyNode;
use crate::model::HarnessMode;
use crate::observation::{RawHarnessError, RawTurnOutput};

/// Kill-switch and budget state recorded into evidence by LOCAL_SYNTHETIC.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiTurnControlSnapshot {
    pub kill_switch: String,
    pub operations: u32,
    pub state_changes: u32,
    pub external_egress_bytes: u64,
}

pub trait ConversationAdapter {
    fn mode(&self) -> HarnessMode;

    /// The target's response to `node`, given every earlier turn of `state`.
    ///
    /// Precondition: `node` is the node the runner selected and `state`
    /// already holds all prior turns of this conversation.
    fn respond(
        &mut self,
        state: &ConversationState,
        node: &StrategyNode,
    ) -> Result<RawTurnOutput, RawHarnessError>;

    /// Called once after every conversation has run. A replay adapter uses it
    /// to report recorded turns that were never consumed.
    fn finish(&mut self) -> Result<(), RawHarnessError> {
        Ok(())
    }

    /// The chain digest a replayed transcript recorded for this turn, if any.
    /// The runner compares it with the recomputed chain and refuses a
    /// mismatch as tampering before anything is evaluated.
    fn recorded_chain_digest(&self, _conversation: &str, _index: u32) -> Option<String> {
        None
    }

    /// Cycle 009 control state, for adapters that run under it.
    fn control_snapshot(&self) -> Option<MultiTurnControlSnapshot> {
        None
    }
}
