use focus_core::{
    SessionEvent, SessionMachine, SessionState, TransitionContext, TransitionError,
};

#[test]
fn locked_session_cannot_end_early_without_emergency_authorization() {
    let result = SessionMachine::apply(
        SessionState::Locked,
        SessionEvent::EndRequested,
        &TransitionContext::new(500, 1_000),
    );

    assert_eq!(result, Err(TransitionError::MinimumDurationNotReached));
}

#[test]
fn locked_session_can_end_after_minimum_duration() {
    let next = SessionMachine::apply(
        SessionState::Locked,
        SessionEvent::EndRequested,
        &TransitionContext::new(1_000, 1_000),
    )
    .unwrap();

    assert_eq!(next.to(), SessionState::Ending);
}

#[test]
fn emergency_authorization_requires_explicit_pending_state() {
    let pending = SessionMachine::apply(
        SessionState::Locked,
        SessionEvent::EmergencyRequested,
        &TransitionContext::new(500, 1_000),
    )
    .unwrap();
    let authorized = SessionMachine::apply(
        pending.to(),
        SessionEvent::EmergencyAuthorized,
        &TransitionContext::new(500, 1_000),
    )
    .unwrap();
    let ending = SessionMachine::apply(
        authorized.to(),
        SessionEvent::EndRequested,
        &TransitionContext::new(500, 1_000),
    )
    .unwrap();

    assert_eq!(ending.to(), SessionState::Ending);
}

#[test]
fn ending_can_transition_to_idle() {
    let next = SessionMachine::apply(
        SessionState::Ending,
        SessionEvent::EndCompleted,
        &TransitionContext::new(1_000, 1_000),
    )
    .unwrap();

    assert_eq!(next.to(), SessionState::Idle);
}

#[test]
fn locked_session_cannot_jump_directly_to_idle() {
    let result = SessionMachine::apply(
        SessionState::Locked,
        SessionEvent::EndCompleted,
        &TransitionContext::new(1_000, 1_000),
    );

    assert_eq!(result, Err(TransitionError::InvalidTransition));
}
