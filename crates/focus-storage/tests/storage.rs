use focus_core::{
    Decision, PolicySet, PolicyVersion, Profile, ProfileId, RecoveryCodeHash, SessionId,
    SessionState,
};
use focus_storage::{FocusStore, SqliteStore, StoredActiveSession, Transition};

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";

fn stored_session(id: u128, state: SessionState) -> StoredActiveSession {
    StoredActiveSession::new(
        SessionId(id),
        state,
        Profile::new(
            ProfileId(1),
            PolicyVersion(1),
            PolicySet::new(Decision::Allow),
        )
        .snapshot(),
        1_000,
        2_000,
        RecoveryCodeHash::from_code(CODE),
    )
}

#[test]
fn stores_and_transitions_the_active_session() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session = stored_session(1, SessionState::Arming);

    store.set_active_session(&session).unwrap();
    store
        .persist_transition(&Transition::new(
            session.id(),
            SessionState::Arming,
            SessionState::Locked,
        ))
        .unwrap();

    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.id(), session.id());
    assert_eq!(active.state(), SessionState::Locked);
    assert_eq!(active.policy_sha256(), session.policy_sha256());
}

#[test]
fn failed_transition_rolls_back_all_database_changes() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session = stored_session(2, SessionState::Arming);

    store.set_active_session(&session).unwrap();

    let result = store.persist_transition(&Transition::new(
        session.id(),
        SessionState::Locked,
        SessionState::Ending,
    ));

    assert!(result.is_err());
    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.state(), SessionState::Arming);
    assert_eq!(active.policy_sha256(), session.policy_sha256());
    assert_eq!(store.transition_count().unwrap(), 0);
}
