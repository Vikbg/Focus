use focus_core::{
    BootId, Decision, EmergencyClockEvent, EmergencyClockSample, EmergencyDecision,
    EmergencyRequest, PolicySet, PolicyVersion, Profile, ProfileId, RecoveryCodeHash, SessionId,
    SessionState,
};
use focus_storage::{FocusStore, SqliteStore, StoredActiveSession};
use focusd::{
    begin_linux_emergency_request, evaluate_emergency_unlock, evaluate_linux_emergency_unlock,
};

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";
const BOOT_A: BootId = BootId(0xaaaa);

const fn sample(monotonic_seconds: u64, unix_seconds: u64) -> EmergencyClockSample {
    EmergencyClockSample::new(BOOT_A, monotonic_seconds, unix_seconds)
}

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

#[test]
fn production_emergency_path_samples_linux_clock_internally() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session = stored_session(6, SessionState::Locked);
    store.set_active_session(&session).unwrap();
    let mut request =
        begin_linux_emergency_request(&mut store, "Need a real emergency exit").unwrap();

    let evaluation = evaluate_linux_emergency_unlock(&mut store, &mut request, CODE).unwrap();

    assert!(matches!(
        evaluation.decision(),
        EmergencyDecision::Waiting { remaining_seconds } if remaining_seconds > 0
    ));
}

#[test]
fn wall_clock_anomaly_is_journaled_and_timing_progress_is_persisted() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session = stored_session(8, SessionState::EmergencyPending);
    store.set_active_session(&session).unwrap();
    let mut request = EmergencyRequest::new(
        session.id(),
        "Need a real emergency exit",
        sample(100, 1_000),
    )
    .unwrap();
    store.persist_emergency_request(&request).unwrap();

    let evaluation =
        evaluate_emergency_unlock(&mut store, &mut request, sample(160, 1_600), CODE).unwrap();

    assert_eq!(
        evaluation.decision(),
        EmergencyDecision::Waiting {
            remaining_seconds: 540,
        }
    );
    assert_eq!(
        evaluation.clock_event(),
        EmergencyClockEvent::WallClockAnomaly
    );
    assert_eq!(store.security_event_count().unwrap(), 1);
    assert_eq!(
        store
            .emergency_request()
            .unwrap()
            .unwrap()
            .timing_state()
            .verified_elapsed_seconds(),
        60
    );
}

#[test]
fn monotonic_regression_moves_active_session_to_protection_failure() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session = stored_session(7, SessionState::EmergencyPending);
    store.set_active_session(&session).unwrap();
    let mut request = EmergencyRequest::new(
        session.id(),
        "Need a real emergency exit",
        sample(100, 1_000),
    )
    .unwrap();
    store.persist_emergency_request(&request).unwrap();

    let evaluation =
        evaluate_emergency_unlock(&mut store, &mut request, sample(99, 1_001), CODE).unwrap();

    assert_eq!(
        evaluation.decision(),
        EmergencyDecision::ClockIntegrityFailure
    );
    assert_eq!(
        evaluation.clock_event(),
        EmergencyClockEvent::MonotonicRegression
    );
    assert_eq!(store.security_event_count().unwrap(), 1);
    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.state(), SessionState::ProtectionFailure);
    assert_eq!(active.policy_sha256(), session.policy_sha256());
}
