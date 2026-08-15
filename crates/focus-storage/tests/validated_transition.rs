use focus_core::{
    Decision, PolicySet, PolicyVersion, Profile, ProfileId, RecoveryCodeHash, SessionEvent,
    SessionId, SessionMachine, SessionState, TransitionContext,
};
use focus_storage::{FocusStore, SqliteStore, StoredActiveSession};

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";

fn stored_session() -> StoredActiveSession {
    StoredActiveSession::new(
        SessionId(55),
        SessionState::Arming,
        Profile::new(
            ProfileId(7),
            PolicyVersion(3),
            PolicySet::new(Decision::Allow),
        )
        .snapshot(),
        500,
        1_000,
        RecoveryCodeHash::from_code(CODE),
    )
}

#[test]
fn storage_accepts_only_a_domain_validated_transition() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session = stored_session();
    store.set_active_session(&session).unwrap();

    let transition = SessionMachine::apply(
        SessionState::Arming,
        SessionEvent::ArmSucceeded,
        &TransitionContext::new(500, 1_000),
    )
    .unwrap();

    store.persist_transition(session.id(), &transition).unwrap();

    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::Locked
    );
}
