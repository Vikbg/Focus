use focus_core::{
    BootId, Decision, EmergencyClockSample, EmergencyRequest, PolicySet, PolicyVersion, Profile,
    ProfileId, RecoveryCodeHash, SessionId, SessionState,
};
use focus_storage::{FocusStore, SqliteStore, StoredActiveSession};

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";

fn active_session() -> StoredActiveSession {
    StoredActiveSession::new(
        SessionId(901),
        SessionState::EmergencyPending,
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
fn persisted_emergency_request_remains_bound_to_active_session() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let active = active_session();
    store.set_active_session(&active).unwrap();

    let request = EmergencyRequest::new(
        active.id(),
        "Need to leave for a real emergency",
        EmergencyClockSample::new(BootId(44), 100, 1_000),
    )
    .unwrap();
    store.persist_emergency_request(&request).unwrap();

    let restored = store.emergency_request().unwrap().unwrap();
    assert_eq!(restored.session_id(), active.id());
    assert_eq!(
        store
            .active_session()
            .unwrap()
            .unwrap()
            .recovery_code_hash(),
        active.recovery_code_hash()
    );
}
