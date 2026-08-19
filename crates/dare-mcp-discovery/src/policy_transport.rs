//! Policy-gated outbound dispatcher.
//!
//! The only public sending entrypoint is [`PolicyGuardedTransport::dispatch`].
//! Callers must not send through a raw [`OutboundTransport`] from this crate.

use super::policy_error::PolicyError;
use super::PassivePolicy;

/// Project-owned outbound dispatcher. Implementors record or send a method
/// that has already been authorized by [`PolicyGuardedTransport`].
pub trait OutboundTransport {
    /// Send an authorized method. Implementations must not be used as the
    /// public sending API; wrap them in [`PolicyGuardedTransport`].
    fn dispatch(&mut self, method: &str) -> Result<(), PolicyError>;
}

/// Outbound transport that authorizes every method before the inner dispatch.
pub struct PolicyGuardedTransport<T, P = super::DefaultPolicy> {
    policy: P,
    transport: T,
}

impl<T, P> PolicyGuardedTransport<T, P>
where
    T: OutboundTransport,
    P: PassivePolicy,
{
    /// Wrap `transport` so every send is checked by `policy` first.
    pub fn new(policy: P, transport: T) -> Self {
        Self { policy, transport }
    }

    /// Authorize `method`, then dispatch. On [`PolicyRefusal`], the inner
    /// transport is not called.
    pub fn dispatch(&mut self, method: &str) -> Result<(), PolicyError> {
        match self.policy.authorize(method) {
            Ok(()) => self.transport.dispatch(method),
            Err(refusal) => Err(PolicyError::from(refusal)),
        }
    }
}
