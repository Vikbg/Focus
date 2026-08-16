use focus_core::ProcessEnforcementPlan;

/// Error returned by the continuous Linux process-execution guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessGuardError {
    Unavailable,
    Unhealthy,
    DisarmFailed,
}

/// Continuous process-execution enforcement owned by the Linux backend.
///
/// Implementations must make `arm` idempotent for the same frozen policy digest. Recovery can
/// repeat the call after the platform effect completed but before protected daemon state advanced.
pub trait ProcessGuardControl {
    /// Arms continuous execution prevention against the exact frozen process plan.
    fn arm(&mut self, plan: &ProcessEnforcementPlan) -> Result<(), ProcessGuardError>;

    /// Verifies that the guard is healthy and enforcing the expected frozen policy digest.
    fn verify(&mut self, expected_policy_digest: [u8; 32]) -> Result<(), ProcessGuardError>;

    /// Stops the continuous process guard. The operation must be idempotent.
    fn disarm(&mut self) -> Result<(), ProcessGuardError>;
}

/// Default controller used until a production continuous process guard is explicitly wired.
///
/// It deliberately refuses arm and verify so Linux can never report the Process guard healthy by
/// construction alone.
#[derive(Debug, Default, Clone, Copy)]
pub struct FailClosedProcessGuard;

impl ProcessGuardControl for FailClosedProcessGuard {
    fn arm(&mut self, _plan: &ProcessEnforcementPlan) -> Result<(), ProcessGuardError> {
        Err(ProcessGuardError::Unavailable)
    }

    fn verify(&mut self, _expected_policy_digest: [u8; 32]) -> Result<(), ProcessGuardError> {
        Err(ProcessGuardError::Unhealthy)
    }

    fn disarm(&mut self) -> Result<(), ProcessGuardError> {
        Ok(())
    }
}
