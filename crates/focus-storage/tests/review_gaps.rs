use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use focus_core::{
    BootId, Decision, EMERGENCY_DELAY_SECONDS, EmergencyClockEvent, EmergencyClockSample,
    EmergencyDecision, EmergencyRequest, PolicySet, PolicyVersion, Profile, ProfileId,
    RecoveryCodeHash, SessionId, SessionState,
};
use focus_storage::{FocusStore, SecurityEvent, SqliteStore, StoredActiveSession};
use rusqlite::Connection;

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";
const BOOT_A: BootId = BootId(0xaaaa);
const BOOT_B: BootId = BootId(0xbbbb);

const fn sample(
    boot_id: BootId,
    monotonic_seconds: u64,
    unix_seconds: u64,
) -> EmergencyClockSample {
    EmergencyClockSample::new(boot_id, monotonic_seconds, unix_seconds)
}

fn temp_database(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("focus-{name}-{nonce}.db"))
}

fn stored_session(id: u128) -> StoredActiveSession {
    StoredActiveSession::new(
        SessionId(id),
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
fn security_events_are_appended_to_the_protected_journal() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let event = SecurityEvent::new("emergency_requested", b"session=42".to_vec());

    store.append_security_event(&event).unwrap();

    assert_eq!(store.security_event_count().unwrap(), 1);
}

#[test]
fn failed_security_journal_write_rolls_back_emergency_timing() {
    let path = temp_database("atomic-emergency-observation");
    let mut store = SqliteStore::open(&path).unwrap();
    let session = stored_session(42);
    store.set_active_session(&session).unwrap();
    let original = EmergencyRequest::new(
        session.id(),
        "Need a real emergency exit",
        sample(BOOT_A, 100, 1_000),
    )
    .unwrap();
    store.persist_emergency_request(&original).unwrap();

    let mut candidate = original.clone();
    let evaluation = candidate.evaluate(
        sample(BOOT_A, 160, 1_600),
        session.recovery_code_hash(),
        CODE,
    );
    assert_eq!(
        evaluation.clock_event(),
        EmergencyClockEvent::WallClockAnomaly
    );
    let event = SecurityEvent::new("emergency_clock_wall_anomaly", b"clock-jump".to_vec());

    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER fail_security_event
             BEFORE INSERT ON security_events
             BEGIN
                 SELECT RAISE(ABORT, 'forced journal failure');
             END;",
        )
        .unwrap();

    let result = store.persist_emergency_observation(&candidate, Some(&event), None);
    assert!(result.is_err());

    let restored = store.emergency_request().unwrap().unwrap();
    assert_eq!(restored.timing_state(), original.timing_state());
    assert_eq!(store.security_event_count().unwrap(), 0);

    drop(store);
    drop(connection);
    let _ = fs::remove_file(&path);
}

#[test]
fn emergency_request_survives_database_reopen_with_verified_monotonic_progress() {
    let path = temp_database("emergency");
    let session = stored_session(43);
    let mut request = EmergencyRequest::new(
        session.id(),
        "Need a real emergency exit",
        sample(BOOT_A, 100, 5_000),
    )
    .unwrap();
    let checkpoint = request.evaluate(
        sample(BOOT_A, 400, 5_300),
        session.recovery_code_hash(),
        CODE,
    );
    assert_eq!(
        checkpoint.decision(),
        EmergencyDecision::Waiting {
            remaining_seconds: 300,
        }
    );

    {
        let mut store = SqliteStore::open(&path).unwrap();
        store.set_active_session(&session).unwrap();
        store.persist_emergency_request(&request).unwrap();
    }

    let store = SqliteStore::open(&path).unwrap();
    let mut restored = store.emergency_request().unwrap().unwrap();

    assert_eq!(restored.session_id(), request.session_id());
    assert_eq!(restored.reason(), request.reason());
    assert_eq!(restored.requested_at(), request.requested_at());
    assert_eq!(restored.timing_state(), request.timing_state());

    let reboot = restored.evaluate(
        sample(BOOT_B, 10, 50_000),
        session.recovery_code_hash(),
        CODE,
    );
    assert_eq!(
        reboot.decision(),
        EmergencyDecision::Waiting {
            remaining_seconds: 300,
        }
    );
    assert_eq!(reboot.clock_event(), EmergencyClockEvent::RebootDetected);

    let completed = restored.evaluate(
        sample(BOOT_B, 310, 50_300),
        session.recovery_code_hash(),
        CODE,
    );
    assert_eq!(completed.decision(), EmergencyDecision::Authorized);

    drop(store);
    let _ = fs::remove_file(&path);
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

#[test]
fn emergency_delay_constant_remains_ten_minutes() {
    assert_eq!(EMERGENCY_DELAY_SECONDS, 600);
}
