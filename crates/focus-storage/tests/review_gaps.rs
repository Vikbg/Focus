use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use focus_core::{EMERGENCY_DELAY_SECONDS, EmergencyDecision, EmergencyRequest};
use focus_storage::{FocusStore, SecurityEvent, SqliteStore};
use rusqlite::Connection;

fn temp_database(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("focus-{name}-{nonce}.db"))
}

#[test]
fn security_events_are_appended_to_the_protected_journal() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let event = SecurityEvent::new("emergency_requested", b"session=42".to_vec());

    store.append_security_event(&event).unwrap();

    assert_eq!(store.security_event_count().unwrap(), 1);
}

#[test]
fn emergency_request_survives_database_reopen_with_original_deadline() {
    const CODE: &str = "FG7K-P29M-4TXQ-R8VN";
    let path = temp_database("emergency");
    let request = EmergencyRequest::new("Need a real emergency exit", 5_000, CODE).unwrap();

    {
        let mut store = SqliteStore::open(&path).unwrap();
        store.persist_emergency_request(&request).unwrap();
    }

    let store = SqliteStore::open(&path).unwrap();
    let restored = store.emergency_request().unwrap().unwrap();
    let _ = fs::remove_file(&path);

    assert_eq!(restored.reason(), request.reason());
    assert_eq!(restored.requested_at(), request.requested_at());
    assert_eq!(
        restored.evaluate(5_000 + EMERGENCY_DELAY_SECONDS - 1, CODE),
        EmergencyDecision::Waiting {
            remaining_seconds: 1
        }
    );
    assert_eq!(
        restored.evaluate(5_000 + EMERGENCY_DELAY_SECONDS, CODE),
        EmergencyDecision::Authorized
    );
}

#[test]
fn migration_failure_is_reported_without_panicking() {
    let path = temp_database("bad-migration");
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE VIEW active_session AS SELECT 1 AS singleton;")
            .unwrap();
    }

    let result = SqliteStore::open(&path);
    let _ = fs::remove_file(&path);

    assert!(result.is_err());
}
