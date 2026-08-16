use focus_core::{
    PolicyVersion, ProfileId, RecoveryCodeHash, SessionId, SessionPolicySnapshot, SessionState,
};
use focus_storage::{FocusStore, SqliteStore, StoredActiveSession};

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";

#[test]
fn stored_active_session_preserves_legacy_policy_schema_and_digest() {
    let snapshot = SessionPolicySnapshot::restore(
        ProfileId(41),
        PolicyVersion(7),
        1,
        &[0],
    )
    .expect("legacy v1 policy snapshot must remain readable");
    let expected_digest = snapshot.policy_sha256();
    let session = StoredActiveSession::new(
        SessionId(0x4100),
        SessionState::Locked,
        snapshot,
        1_000,
        2_000,
        RecoveryCodeHash::from_code(CODE),
    );
    let mut store = SqliteStore::open_in_memory().unwrap();

    store.set_active_session(&session).unwrap();
    let restored = store.active_session().unwrap().unwrap();

    assert_eq!(restored.policy_snapshot().schema_version(), 1);
    assert_eq!(restored.policy_sha256(), expected_digest);
    assert!(restored.policy_snapshot().process_enforcement_plan().is_none());
}
