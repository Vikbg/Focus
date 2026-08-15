use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use focus_core::{
    BootId, EMERGENCY_DELAY_SECONDS, EmergencyClockEvent, EmergencyClockSample, EmergencyDecision,
    EmergencyRequest,
};
use focus_storage::{FocusStore, SecurityEvent, SqliteStore};
use rusqlite::Connection;

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";
const BOOT_A: BootId = BootId(0xaaaa);
const BOOT_B: BootId = BootId(0xbbbb);

const fn sample(boot_id: BootId, monotonic_seconds: u64, unix_seconds: u64) -> EmergencyClockSample {
    EmergencyClockSample::new(boot_id, monotonic_seconds, unix_seconds)
}

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
fn emergency_request_survives_database_reopen_with_verified_monotonic_progress() {
    let path = temp_database("emergency");
    let mut request = EmergencyRequest::new(
        "Need a real emergency exit",
        sample(BOOT_A, 100, 5_000),
        CODE,
    )
    .unwrap();
    let checkpoint = request.evaluate(sample(BOOT_A, 400, 5_300), CODE);
    assert_eq!(
        checkpoint.decision(),
        EmergencyDecision::Waiting {
            remaining_seconds: 300,
        }
    );

    {
        let mut store = SqliteStore::open(&path).unwrap();
        store.persist_emergency_request(&request).unwrap();
    }

    let store = SqliteStore::open(&path).unwrap();
    let mut restored = store.emergency_request().unwrap().unwrap();
    let _ = fs::remove_file(&path);

    assert_eq!(restored.reason(), request.reason());
    assert_eq!(restored.requested_at(), request.requested_at());
    assert_eq!(restored.timing_state(), request.timing_state());

    let reboot = restored.evaluate(sample(BOOT_B, 10, 50_000), CODE);
    assert_eq!(
        reboot.decision(),
        EmergencyDecision::Waiting {
            remaining_seconds: 300,
        }
    );
    assert_eq!(reboot.clock_event(), EmergencyClockEvent::RebootDetected);

    let completed = restored.evaluate(sample(BOOT_B, 310, 50_300), CODE);
    assert_eq!(completed.decision(), EmergencyDecision::Authorized);
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
