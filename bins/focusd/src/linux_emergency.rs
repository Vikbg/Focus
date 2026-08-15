use std::{error::Error, fmt};

use focus_core::{EmergencyError, EmergencyEvaluation, EmergencyRequest};
use focus_linux::ClockSampleError;
use focus_storage::{FocusStore, StoreError};

use crate::{EmergencyUnlockError, evaluate_emergency_unlock};

/// Error returned by the production Linux emergency-unlock timing path.
#[derive(Debug)]
pub enum LinuxEmergencyError {
    Clock(ClockSampleError),
    Domain(EmergencyError),
    Store(StoreError),
    Evaluation(EmergencyUnlockError),
}

impl fmt::Display for LinuxEmergencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clock(error) => write!(formatter, "emergency clock error: {error}"),
            Self::Domain(error) => write!(formatter, "emergency request error: {error:?}"),
            Self::Store(error) => write!(formatter, "emergency store error: {error}"),
            Self::Evaluation(error) => write!(formatter, "emergency evaluation error: {error}"),
        }
    }
}

impl Error for LinuxEmergencyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Clock(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Evaluation(error) => Some(error),
            Self::Domain(_) => None,
        }
    }
}

impl From<ClockSampleError> for LinuxEmergencyError {
    fn from(error: ClockSampleError) -> Self {
        Self::Clock(error)
    }
}

impl From<EmergencyError> for LinuxEmergencyError {
    fn from(error: EmergencyError) -> Self {
        Self::Domain(error)
    }
}

impl From<StoreError> for LinuxEmergencyError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<EmergencyUnlockError> for LinuxEmergencyError {
    fn from(error: EmergencyUnlockError) -> Self {
        Self::Evaluation(error)
    }
}

/// Creates and persists an emergency request using trusted Linux clock sources.
///
/// # Errors
///
/// Returns an error when the Linux clock cannot be sampled, the request is invalid,
/// or the protected store cannot persist it.
pub fn begin_linux_emergency_request<S: FocusStore>(
    store: &mut S,
    reason: &str,
    recovery_code: &str,
) -> Result<EmergencyRequest, LinuxEmergencyError> {
    let clock = focus_linux::sample_emergency_clock()?;
    let request = EmergencyRequest::new(reason, clock, recovery_code)?;
    store.persist_emergency_request(&request)?;
    Ok(request)
}

/// Evaluates an emergency request using a clock sample obtained inside the daemon.
///
/// # Errors
///
/// Returns an error when the Linux clock cannot be sampled, protected state cannot be updated,
/// or the authoritative state machine rejects a required protection-failure transition.
pub fn evaluate_linux_emergency_unlock<S: FocusStore>(
    store: &mut S,
    request: &mut EmergencyRequest,
    recovery_code: &str,
) -> Result<EmergencyEvaluation, LinuxEmergencyError> {
    let clock = focus_linux::sample_emergency_clock()?;
    evaluate_emergency_unlock(store, request, clock, recovery_code).map_err(Into::into)
}
