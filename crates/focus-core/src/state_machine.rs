//! Focus session lifecycle states and transition guards.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Preflight,
    Arming,
    Locked,
    EmergencyPending,
    EmergencyAuthorized,
    Ending,
    Recovering,
    ProtectionFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    MinimumDurationNotReached,
    InvalidTransition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionGuard {
    state: SessionState,
    minimum_duration_reached: bool,
    emergency_authorized: bool,
}

impl SessionGuard {
    #[must_use]
    pub const fn locked(minimum_duration_reached: bool, emergency_authorized: bool) -> Self {
        Self {
            state: SessionState::Locked,
            minimum_duration_reached,
            emergency_authorized,
        }
    }

    #[must_use]
    pub const fn ending() -> Self {
        Self {
            state: SessionState::Ending,
            minimum_duration_reached: true,
            emergency_authorized: false,
        }
    }

    #[must_use]
    pub const fn state(self) -> SessionState {
        self.state
    }

    /// Moves this guard to an allowed next state.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::MinimumDurationNotReached`] when a locked
    /// session attempts to end before its minimum duration without emergency
    /// authorization. Returns [`TransitionError::InvalidTransition`] for every
    /// transition that is not explicitly allowed by the state machine.
    pub const fn transition(self, target: SessionState) -> Result<Self, TransitionError> {
        match (self.state, target) {
            (SessionState::Locked, SessionState::Ending)
                if !self.minimum_duration_reached && !self.emergency_authorized =>
            {
                Err(TransitionError::MinimumDurationNotReached)
            }
            (SessionState::Locked, SessionState::Ending) => Ok(Self {
                state: SessionState::Ending,
                ..self
            }),
            (SessionState::Ending, SessionState::Idle) => Ok(Self {
                state: SessionState::Idle,
                ..self
            }),
            _ => Err(TransitionError::InvalidTransition),
        }
    }
}
