use std::collections::{HashSet, VecDeque};

use focus_core::{
    SessionEvent, SessionMachine, SessionState, TransitionContext, TransitionError,
};

const BEFORE_MINIMUM: TransitionContext = TransitionContext::new(500, 1_000);
const AFTER_MINIMUM: TransitionContext = TransitionContext::new(1_000, 1_000);

fn apply(state: SessionState, event: SessionEvent, context: &TransitionContext) -> SessionState {
    SessionMachine::apply(state, event, context).unwrap().to()
}

#[test]
fn normal_flow_is_owned_by_one_transition_engine() {
    let state = apply(
        SessionState::Idle,
        SessionEvent::BeginPreflight,
        &BEFORE_MINIMUM,
    );
    assert_eq!(state, SessionState::Preflight);

    let state = apply(state, SessionEvent::PreflightPassed, &BEFORE_MINIMUM);
    assert_eq!(state, SessionState::Arming);

    let state = apply(state, SessionEvent::ArmSucceeded, &BEFORE_MINIMUM);
    assert_eq!(state, SessionState::Locked);

    let state = apply(state, SessionEvent::EndRequested, &AFTER_MINIMUM);
    assert_eq!(state, SessionState::Ending);

    let state = apply(state, SessionEvent::EndCompleted, &AFTER_MINIMUM);
    assert_eq!(state, SessionState::Idle);
}

#[test]
fn emergency_flow_requires_explicit_pending_and_authorized_states() {
    let state = apply(
        SessionState::Locked,
        SessionEvent::EmergencyRequested,
        &BEFORE_MINIMUM,
    );
    assert_eq!(state, SessionState::EmergencyPending);

    let state = apply(
        state,
        SessionEvent::EmergencyAuthorized,
        &BEFORE_MINIMUM,
    );
    assert_eq!(state, SessionState::EmergencyAuthorized);

    let state = apply(state, SessionEvent::EndRequested, &BEFORE_MINIMUM);
    assert_eq!(state, SessionState::Ending);
}

#[test]
fn recovery_flow_can_only_restore_locked_or_fail_closed() {
    let recovering = apply(
        SessionState::Locked,
        SessionEvent::RecoveryStarted,
        &BEFORE_MINIMUM,
    );
    assert_eq!(recovering, SessionState::Recovering);

    let locked = apply(
        recovering,
        SessionEvent::RecoverySucceeded,
        &BEFORE_MINIMUM,
    );
    assert_eq!(locked, SessionState::Locked);

    let failed = apply(
        SessionState::Recovering,
        SessionEvent::ProtectionFailed,
        &BEFORE_MINIMUM,
    );
    assert_eq!(failed, SessionState::ProtectionFailure);
}

#[test]
fn arming_failure_has_an_explicit_fail_closed_edge() {
    let state = apply(
        SessionState::Arming,
        SessionEvent::ArmFailed,
        &BEFORE_MINIMUM,
    );
    assert_eq!(state, SessionState::ProtectionFailure);
}

#[test]
fn locked_session_cannot_end_before_minimum_without_emergency_flow() {
    let result = SessionMachine::apply(
        SessionState::Locked,
        SessionEvent::EndRequested,
        &BEFORE_MINIMUM,
    );

    assert_eq!(result, Err(TransitionError::MinimumDurationNotReached));
}

#[test]
fn validated_transition_exposes_facts_but_not_an_arbitrary_target_api() {
    let transition = SessionMachine::apply(
        SessionState::Arming,
        SessionEvent::ArmSucceeded,
        &BEFORE_MINIMUM,
    )
    .unwrap();

    assert_eq!(transition.from(), SessionState::Arming);
    assert_eq!(transition.to(), SessionState::Locked);
    assert_eq!(transition.event(), SessionEvent::ArmSucceeded);
}

#[test]
fn model_has_no_locked_to_idle_route_before_minimum_without_emergency_events() {
    const NON_EMERGENCY_EVENTS: [SessionEvent; 9] = [
        SessionEvent::BeginPreflight,
        SessionEvent::PreflightPassed,
        SessionEvent::ArmSucceeded,
        SessionEvent::ArmFailed,
        SessionEvent::RecoveryStarted,
        SessionEvent::RecoverySucceeded,
        SessionEvent::ProtectionFailed,
        SessionEvent::EndRequested,
        SessionEvent::EndCompleted,
    ];

    let mut queue = VecDeque::from([SessionState::Locked]);
    let mut visited = HashSet::from([SessionState::Locked]);

    while let Some(state) = queue.pop_front() {
        assert_ne!(state, SessionState::Idle);

        for event in NON_EMERGENCY_EVENTS {
            let Ok(transition) = SessionMachine::apply(state, event, &BEFORE_MINIMUM) else {
                continue;
            };
            if visited.insert(transition.to()) {
                queue.push_back(transition.to());
            }
        }
    }
}
