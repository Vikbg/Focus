use focus_core::{
    Decision, EmergencyClockSample, EmergencyDecision, EmergencyRequest, PolicySet, PolicyVersion,
    Profile, ProfileId, RecoveryCodeHash, SessionId, SessionState,
};
use focus_storage::{FocusStore, SqliteStore, StoredActiveSession};
use focusd::{
    EmergencyUnlockError, begin_linux_emergency_request, evaluate_emergency_unlock,
};

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";
const WRONG_CODE: &str = "ZZZZ-ZZZZ-ZZZZ-ZZZZ";
const NANOS_PER_SECOND: u64 = 1_000_000_000;

fn stored_session(id: u128, state: SessionState) -> StoredActiveSession {
    StoredActiveSession::new(
        SessionId(id),
        state,
        Profile::new(
            ProfileId(7),
            PolicyVersion(3),
            PolicySet::new(Decision::Allow),
        )
        .snapshot(),
        1_000,
        2_000,
        RecoveryCodeHash::from_code(CODE),
    )
}

fn completed_clock(request: &EmergencyRequest) -> EmergencyClockSample {
    let timing = request.timing_state();
    EmergencyClockSample::new_nanos(
        timing.boot_id(),
        timing
            .monotonic_anchor_nanos()
            .saturating_add(600 * NANOS_PER_SECOND),
        timing.unix_anchor_seconds().saturating_add(600),
    )
}

#[test]
fn requesting_emergency_enters_pending_without_replacing_precommitted_code() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session = stored_session(70, SessionState::Locked);
    let expected_hash = session.recovery_code_hash();
    store.set_active_session(&session).unwrap();

    let request = begin_linux_emergency_request(&mut store, "Need to leave now").unwrap();

    assert_eq!(request.session_id(), session.id());
    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.state(), SessionState::EmergencyPending);
    assert_eq!(active.recovery_code_hash(), expected_hash);
}

#[test]
fn wrong_code_never_changes_pending_session_state() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session = stored_session(71, SessionState::Locked);
    store.set_active_session(&session).unwrap();
    let mut request = begin_linux_emergency_request(&mut store, "Need to leave now").unwrap();

    let evaluation = evaluate_emergency_unlock(
        &mut store,
        &mut request,
        completed_clock(&request),
        WRONG_CODE,
    )
    .unwrap();

    assert_eq!(evaluation.decision(), EmergencyDecision::InvalidCode);
    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::EmergencyPending
    );
}

#[test]
fn authorized_code_advances_pending_to_authorized_then_ending() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session = stored_session(72, SessionState::Locked);
    store.set_active_session(&session).unwrap();
    let mut request = begin_linux_emergency_request(&mut store, "Need to leave now").unwrap();

    let evaluation = evaluate_emergency_unlock(
        &mut store,
        &mut request,
        completed_clock(&request),
        CODE,
    )
    .unwrap();

    assert_eq!(evaluation.decision(), EmergencyDecision::Authorized);
    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::Ending
    );
    assert_eq!(store.transition_count().unwrap(), 3);
}

#[test]
fn stale_emergency_request_from_another_session_is_rejected() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session = stored_session(73, SessionState::EmergencyPending);
    store.set_active_session(&session).unwrap();
    let mut stale = EmergencyRequest::new(
        SessionId(999),
        "Old emergency",
        EmergencyClockSample::new(focus_core::BootId(1), 100, 1_000),
    )
    .unwrap();
    let clock = completed_clock(&stale);

    let result = evaluate_emergency_unlock(&mut store, &mut stale, clock, CODE);

    assert!(matches!(result, Err(EmergencyUnlockError::SessionMismatch)));
    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::EmergencyPending
    );
}
