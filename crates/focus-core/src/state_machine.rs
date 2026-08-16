//! Focus session lifecycle states and the authoritative transition engine.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionEvent {
    BeginPreflight,
    PreflightPassed,
    ArmSucceeded,
    ArmFailed,
    RecoveryStarted,
    RecoverySucceeded,
    ProtectionFailed,
    EmergencyRequested,
    EmergencyAuthorized,
    EndRequested,
    EndCompleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    MinimumDurationNotReached,
    InvalidTransition,
}

/// Timing facts required to validate lifecycle transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionContext {
    now_unix_ms: u64,
    minimum_end_at_unix_ms: u64,
}

impl TransitionContext {
    #[must_use]
    pub const fn new(now_unix_ms: u64, minimum_end_at_unix_ms: u64) -> Self {
        Self {
            now_unix_ms,
            minimum_end_at_unix_ms,
        }
    }

    #[must_use]
    pub const fn minimum_duration_reached(self) -> bool {
        self.now_unix_ms >= self.minimum_end_at_unix_ms
    }
}

/// A transition that has been approved by [`SessionMachine`].
///
/// This type intentionally has no public constructor. Callers can inspect the
/// approved facts, but only the domain transition engine can create a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedTransition {
    from: SessionState,
    to: SessionState,
    event: SessionEvent,
}

impl ValidatedTransition {
    #[must_use]
    pub const fn from(self) -> SessionState {
        self.from
    }

    #[must_use]
    pub const fn to(self) -> SessionState {
        self.to
    }

    #[must_use]
    pub const fn event(self) -> SessionEvent {
        self.event
    }
}

/// Single authoritative validator for Focus session lifecycle changes.
pub struct SessionMachine;

impl SessionMachine {
    /// Validates one domain event against the current state and transition context.
    ///
    /// # Errors
    ///
    /// Returns [`TransitionError::MinimumDurationNotReached`] when a normal end is
    /// requested before the frozen minimum end time. Returns
    /// [`TransitionError::InvalidTransition`] for every state/event pair that is not
    /// explicitly part of the normative Focus lifecycle.
    pub const fn apply(
        state: SessionState,
        event: SessionEvent,
        context: &TransitionContext,
    ) -> Result<ValidatedTransition, TransitionError> {
        let target = match (state, event) {
            (SessionState::Idle, SessionEvent::BeginPreflight) => SessionState::Preflight,
            (SessionState::Preflight, SessionEvent::PreflightPassed) => SessionState::Arming,
            (SessionState::Arming, SessionEvent::ArmSucceeded)
            | (SessionState::Recovering, SessionEvent::RecoverySucceeded) => SessionState::Locked,
            (SessionState::Arming, SessionEvent::ArmFailed)
            | (
                SessionState::Preflight
                | SessionState::Arming
                | SessionState::Locked
                | SessionState::EmergencyPending
                | SessionState::EmergencyAuthorized
                | SessionState::Ending
                | SessionState::Recovering,
                SessionEvent::ProtectionFailed,
            ) => SessionState::ProtectionFailure,
            (SessionState::Arming | SessionState::Locked, SessionEvent::RecoveryStarted) => {
                SessionState::Recovering
            }
            (SessionState::Locked, SessionEvent::EmergencyRequested) => {
                SessionState::EmergencyPending
            }
            (SessionState::EmergencyPending, SessionEvent::EmergencyAuthorized) => {
                SessionState::EmergencyAuthorized
            }
            (SessionState::Locked, SessionEvent::EndRequested)
                if !context.minimum_duration_reached() =>
            {
                return Err(TransitionError::MinimumDurationNotReached);
            }
            (
                SessionState::Locked | SessionState::EmergencyAuthorized,
                SessionEvent::EndRequested,
            ) => SessionState::Ending,
            (SessionState::Ending, SessionEvent::EndCompleted) => SessionState::Idle,
            _ => return Err(TransitionError::InvalidTransition),
        };

        Ok(ValidatedTransition {
            from: state,
            to: target,
            event,
        })
    }
}
