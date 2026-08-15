use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use focus_storage::{FocusStore, MutationReservation, SqliteStore};
use rusqlite::Connection;

fn temp_database(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("focus-migration-{name}-{nonce}.db"))
}

fn create_v1(path: &Path) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
             INSERT INTO schema_migrations(version) VALUES(1);

             CREATE TABLE active_session (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 session_id TEXT NOT NULL,
                 state INTEGER NOT NULL
             );
             CREATE TABLE session_transitions (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 session_id TEXT NOT NULL,
                 from_state INTEGER NOT NULL,
                 to_state INTEGER NOT NULL
             );
             CREATE TABLE profiles (
                 id TEXT PRIMARY KEY,
                 version INTEGER NOT NULL,
                 payload BLOB NOT NULL
             );
             CREATE TABLE schedules (
                 id TEXT PRIMARY KEY,
                 payload BLOB NOT NULL
             );
             CREATE TABLE vpn_identities (
                 id TEXT PRIMARY KEY,
                 payload BLOB NOT NULL
             );
             CREATE TABLE security_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_type TEXT NOT NULL,
                 payload BLOB NOT NULL
             );
             CREATE TABLE emergency_request (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 reason TEXT NOT NULL,
                 requested_at INTEGER NOT NULL,
                 code_hash BLOB NOT NULL
             );
             CREATE TABLE emergency_timing (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 boot_id TEXT NOT NULL,
                 monotonic_anchor INTEGER NOT NULL,
                 unix_anchor INTEGER NOT NULL,
                 verified_elapsed INTEGER NOT NULL
             );",
        )
        .unwrap();
}

fn upgrade_fixture_to_v2(path: &Path) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "ALTER TABLE active_session ADD COLUMN profile_id TEXT;
             ALTER TABLE active_session ADD COLUMN profile_version INTEGER;
             ALTER TABLE active_session ADD COLUMN policy_schema_version INTEGER;
             ALTER TABLE active_session ADD COLUMN policy_payload BLOB;
             ALTER TABLE active_session ADD COLUMN policy_sha256 BLOB;
             ALTER TABLE active_session ADD COLUMN started_at_unix_ms INTEGER;
             ALTER TABLE active_session ADD COLUMN minimum_end_at_unix_ms INTEGER;
             ALTER TABLE active_session ADD COLUMN recovery_code_hash BLOB;
             INSERT INTO schema_migrations(version) VALUES(2);",
        )
        .unwrap();
}

fn upgrade_fixture_to_v3(path: &Path) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "ALTER TABLE emergency_request ADD COLUMN session_id TEXT;
             INSERT INTO schema_migrations(version) VALUES(3);",
        )
        .unwrap();
}

fn assert_upgrades_to_current(path: &Path, request_id: u128) {
    {
        let mut store = SqliteStore::open(path).unwrap();
        assert_eq!(
            store.reserve_mutation(request_id, b"fixture").unwrap(),
            MutationReservation::Started
        );
    }

    let mut reopened = SqliteStore::open(path).unwrap();
    assert_eq!(
        reopened.reserve_mutation(request_id, b"fixture").unwrap(),
        MutationReservation::InProgress
    );
}

#[test]
fn schema_upgrade_from_v1_reaches_current_schema() {
    let path = temp_database("v1");
    create_v1(&path);

    assert_upgrades_to_current(&path, 101);
    let _ = fs::remove_file(path);
}

#[test]
fn schema_upgrade_from_v2_reaches_current_schema() {
    let path = temp_database("v2");
    create_v1(&path);
    upgrade_fixture_to_v2(&path);

    assert_upgrades_to_current(&path, 102);
    let _ = fs::remove_file(path);
}

#[test]
fn schema_upgrade_from_v3_reaches_current_schema() {
    let path = temp_database("v3");
    create_v1(&path);
    upgrade_fixture_to_v2(&path);
    upgrade_fixture_to_v3(&path);

    assert_upgrades_to_current(&path, 103);
    let _ = fs::remove_file(path);
}
