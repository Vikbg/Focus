use crate::{PrivilegeGuardControl, PrivilegeGuardError};

/// Fail-closed privilege controller used when no production UID-scoped guard was supplied.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FailClosedPrivilegeGuard;

impl PrivilegeGuardControl for FailClosedPrivilegeGuard {
    fn arm(&mut self) -> Result<(), PrivilegeGuardError> {
        Err(PrivilegeGuardError::Unavailable)
    }

    fn verify(&mut self) -> Result<(), PrivilegeGuardError> {
        Err(PrivilegeGuardError::Unhealthy)
    }

    fn disarm(&mut self) -> Result<(), PrivilegeGuardError> {
        Ok(())
    }
}
