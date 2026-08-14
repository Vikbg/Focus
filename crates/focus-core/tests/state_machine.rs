use focus_core::{SessionGuard, SessionState, TransitionError};

#[test]
fn locked_session_cannot_end_early_without_emergency_authorization() {
    let session = SessionGuard::locked(false, false);

    let result = session.transition(SessionState::Ending);

    assert_eq!(result, Err(TransitionError::MinimumDurationNotReached));
}

#[test]
fn locked_session_can_end_after_minimum_duration() {
    let session = SessionGuard::locked(true, false);

    let next = session.transition(SessionState::Ending).unwrap();

    assert_eq!(next.state(), SessionState::Ending);
}

#[test]
fn emergency_authorization_allows_early_end() {
    let session = SessionGuard::locked(false, true);

    let next = session.transition(SessionState::Ending).unwrap();

    assert_eq!(next.state(), SessionState::Ending);
}

#[test]
fn ending_can_transition_to_idle() {
    let session = SessionGuard::ending();

    let next = session.transition(SessionState::Idle).unwrap();

    assert_eq!(next.state(), SessionState::Idle);
}

#[test]
fn locked_session_cannot_jump_directly_to_idle() {
    let session = SessionGuard::locked(true, false);

    let result = session.transition(SessionState::Idle);

    assert_eq!(result, Err(TransitionError::InvalidTransition));
}
