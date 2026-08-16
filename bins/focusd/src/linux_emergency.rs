use std::{error::Error, fmt};

use focus_core::{
    EmergencyError, EmergencyEvaluation, EmergencyRequest, SessionEvent, SessionMachine,
    SessionState, TransitionContext, TransitionError,
};
use focus_linux::ClockSampleError;
use focus_storage::{FocusStore, StoreError};

use crate::{EmergencyUnlockError, evaluate_emergency_unlock};

/// Error returned by the production Linux emergency-unlock timing path.
#[derive(Debug)]
pub enum LinuxEmergencyError {
    Clock(ClockSampleError),
    Domain(EmergencyError),
    Store(StoreError),
    Transition(TransitionError),
    Evaluation(EmergencyUnlockError),
    NoActiveSession,
    InvalidSessionState(SessionState),
}

impl fmt::Display for LinuxEmergencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clock(error) => write!(formatter, "emergency clock error: {error}"),
            Self::Domain(error) => write!(formatter, "emergency request error: {error:?}"),
            Self::Store(error) => write!(formatter, "emergency store error: {error}"),
            Self::Transition(error) => write!(formatter, "emergency transition error: {error:?}"),
            Self::Evaluation(error) => write!(formatter, "emergency evaluation error: {error}"),
            Self::NoActiveSession => formatter.write_str("no active Focus session"),
            Self::InvalidSessionState(state) => {
                write!(
                    formatter,
                    "cannot request emergency unlock from state {state:?}"
                )
            }
        }
    }
}

impl Error for LinuxEmergencyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Clock(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Evaluation(error) => Some(error),
            Self::Domain(_)
            | Self::Transition(_)
            | Self::NoActiveSession
            | Self::InvalidSessionState(_) => None,
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

impl From<TransitionError> for LinuxEmergencyError {
    fn from(error: TransitionError) -> Self {
        Self::Transition(error)
    }
}

impl From<EmergencyUnlockError> for LinuxEmergencyError {
    fn from(error: EmergencyUnlockError) -> Self {
        Self::Evaluation(error)
    }
}

/// Creates and persists an emergency request using trusted Linux clock sources.
///
/// The recovery code is not accepted here. Its hash must already be frozen in the active
/// session. Request creation and `Locked -> EmergencyPending` are committed atomically.
///
/// # Errors
///
/// Returns an error when there is no active locked session, the Linux clock cannot be
/// sampled, the request is invalid, or protected state cannot be persisted.
pub fn begin_linux_emergency_request<S: FocusStore>(
    store: &mut S,
    reason: &str,
) -> Result<EmergencyRequest, LinuxEmergencyError> {
    let active = store
        .active_session()?
        .ok_or(LinuxEmergencyError::NoActiveSession)?;
    if active.state() != SessionState::Locked {
        return Err(LinuxEmergencyError::InvalidSessionState(active.state()));
    }

    let clock = focus_linux::sample_emergency_clock()?;
    let request = EmergencyRequest::new(active.id(), reason, clock)?;
    let context =
        TransitionContext::new(active.started_at_unix_ms(), active.minimum_end_at_unix_ms());
    let pending = SessionMachine::apply(
        SessionState::Locked,
        SessionEvent::EmergencyRequested,
        &context,
    )?;
    store.persist_emergency_observation(&request, None, Some((active.id(), &pending)))?;
    Ok(request)
}

/// Evaluates an emergency request using a clock sample obtained inside the daemon.
///
/// # Errors
///
/// Returns an error when the Linux clock cannot be sampled, the request is stale or not
/// pending, protected state cannot be updated, or the authoritative lifecycle rejects a
/// required transition.
pub fn evaluate_linux_emergency_unlock<S: FocusStore>(
    store: &mut S,
    request: &mut EmergencyRequest,
    recovery_code: &str,
) -> Result<EmergencyEvaluation, LinuxEmergencyError> {
    let clock = focus_linux::sample_emergency_clock()?;
    evaluate_emergency_unlock(store, request, clock, recovery_code).map_err(Into::into)
}
