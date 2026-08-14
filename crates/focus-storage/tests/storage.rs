use focus_core::{SessionId, SessionState};
use focus_storage::{FocusStore, SqliteStore, Transition};

#[test]
fn stores_and_transitions_the_active_session() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session_id = SessionId(1);

    store
        .set_active_session(session_id, SessionState::Arming)
        .unwrap();
    store
        .persist_transition(&Transition::new(
            session_id,
            SessionState::Arming,
            SessionState::Locked,
        ))
        .unwrap();

    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.id(), session_id);
    assert_eq!(active.state(), SessionState::Locked);
}

#[test]
fn failed_transition_rolls_back_all_database_changes() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session_id = SessionId(2);

    store
        .set_active_session(session_id, SessionState::Arming)
        .unwrap();

    let result = store.persist_transition(&Transition::new(
        session_id,
        SessionState::Locked,
        SessionState::Ending,
    ));

    assert!(result.is_err());
    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.state(), SessionState::Arming);
    assert_eq!(store.transition_count().unwrap(), 0);
}
