use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use focus_core::{
    Decision, PolicySet, PolicyVersion, Profile, ProfileId, RecoveryCodeHash, SessionId,
    SessionState,
};
use focus_storage::{FocusStore, SqliteStore, StoreError, StoredActiveSession};
use rusqlite::Connection;

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";

fn temp_database(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("focus-{name}-{nonce}.db"))
}

fn session(session_id: u128) -> StoredActiveSession {
    let snapshot = Profile::new(
        ProfileId(7),
        PolicyVersion(3),
        PolicySet::new(Decision::Allow),
    )
    .snapshot();

    StoredActiveSession::new(
        SessionId(session_id),
        SessionState::Arming,
        snapshot,
        1_000,
        2_000,
        RecoveryCodeHash::from_code(CODE),
    )
}

#[test]
fn active_session_reopen_restores_exact_policy_version_and_digest() {
    let path = temp_database("active-session-snapshot");
    let expected = session(41);
    let expected_digest = expected.policy_sha256();

    {
        let mut store = SqliteStore::open(&path).unwrap();
        store.set_active_session(&expected).unwrap();
    }

    let store = SqliteStore::open(&path).unwrap();
    let restored = store.active_session().unwrap().unwrap();

    assert_eq!(restored, expected);
    assert_eq!(restored.policy_sha256(), expected_digest);
    assert_eq!(restored.policy_snapshot().profile_id(), ProfileId(7));
    assert_eq!(
        restored.policy_snapshot().profile_version(),
        PolicyVersion(3)
    );
    assert_eq!(
        restored.policy_snapshot().policy(),
        PolicySet::new(Decision::Allow)
    );

    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn profile_edit_does_not_change_recovered_locked_session() {
    let path = temp_database("frozen-policy");
    let mut original = session(42);
    original.set_state(SessionState::Locked);

    {
        let mut store = SqliteStore::open(&path).unwrap();
        store.set_active_session(&original).unwrap();
    }

    let edited_profile = Profile::new(
        ProfileId(7),
        PolicyVersion(4),
        PolicySet::new(Decision::Classify),
    );
    assert_ne!(
        edited_profile.snapshot(),
        original.policy_snapshot().clone()
    );

    let store = SqliteStore::open(&path).unwrap();
    let restored = store.active_session().unwrap().unwrap();

    assert_eq!(
        restored.policy_snapshot().profile_version(),
        PolicyVersion(3)
    );
    assert_eq!(
        restored.policy_snapshot().policy(),
        PolicySet::new(Decision::Allow)
    );
    assert_eq!(restored.policy_sha256(), original.policy_sha256());

    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn legacy_active_session_without_security_snapshot_fails_closed_after_migration() {
    let path = temp_database("legacy-active-session");
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "
                CREATE TABLE active_session (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    session_id TEXT NOT NULL,
                    state INTEGER NOT NULL
                );
                INSERT INTO active_session(singleton, session_id, state)
                VALUES(1, '0000000000000000000000000000002b', 3);

                CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY
                );
                ",
            )
            .unwrap();
    }

    let store = SqliteStore::open(&path).unwrap();
    let restored = store.active_session();

    assert!(matches!(restored, Err(StoreError::IncompleteActiveSession)));

    drop(store);
    let _ = fs::remove_file(path);
}

#[test]
fn unknown_future_schema_version_is_rejected() {
    let path = temp_database("future-schema");
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "
                CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY
                );
                INSERT INTO schema_migrations(version) VALUES(999);
                ",
            )
            .unwrap();
    }

    let result = SqliteStore::open(&path);
    assert!(matches!(
        result,
        Err(StoreError::UnsupportedSchemaVersion(999))
    ));

    let _ = fs::remove_file(path);
}
