use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use focus_storage::{FocusStore, MutationReservation, SecurityEvent, SqliteStore};
use rusqlite::{Connection, params};

fn temp_db(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "focus-storage-{name}-{}-{nonce}.db",
        std::process::id()
    ))
}

fn cleanup_db(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(format!("{}-journal", path.display()));
    let _ = fs::remove_file(format!("{}-wal", path.display()));
    let _ = fs::remove_file(format!("{}-shm", path.display()));
}

fn create_v1_schema(connection: &Connection) {
    connection
        .execute_batch(
            "CREATE TABLE schema_migrations (
                 version INTEGER PRIMARY KEY
             );
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

fn advance_fixture_to(connection: &Connection, version: i64) {
    create_v1_schema(connection);
    if version >= 2 {
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
    if version >= 3 {
        connection
            .execute_batch(
                "ALTER TABLE emergency_request ADD COLUMN session_id TEXT;
                 INSERT INTO schema_migrations(version) VALUES(3);",
            )
            .unwrap();
    }
}

#[test]
fn sqlite_corruption_fails_closed_without_panicking() {
    let path = temp_db("corrupt");
    fs::write(&path, b"not a sqlite database").unwrap();

    let result = std::panic::catch_unwind(|| SqliteStore::open(&path));

    assert!(result.is_ok(), "opening corruption must not panic");
    assert!(result.unwrap().is_err(), "corruption must fail closed");
    cleanup_db(&path);
}

#[cfg(unix)]
#[test]
fn read_only_database_cannot_accept_security_writes() {
    use std::os::unix::fs::PermissionsExt;

    let path = temp_db("readonly");
    drop(SqliteStore::open(&path).unwrap());

    let original_mode = fs::metadata(&path).unwrap().permissions().mode();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();

    let failed_closed = match SqliteStore::open(&path) {
        Ok(mut store) => store
            .append_security_event(&SecurityEvent::new("read_only_probe", vec![1, 2, 3]))
            .is_err(),
        Err(_) => true,
    };

    fs::set_permissions(&path, fs::Permissions::from_mode(original_mode)).unwrap();
    cleanup_db(&path);

    assert!(failed_closed, "read-only database accepted a security write");
}

#[test]
fn sqlite_full_rejects_security_event_without_partial_row() {
    let path = temp_db("full");
    drop(SqliteStore::open(&path).unwrap());

    let connection = Connection::open(&path).unwrap();
    let page_count: i64 = connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .unwrap();
    let configured: i64 = connection
        .query_row(
            &format!("PRAGMA max_page_count = {page_count}"),
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(configured, page_count);

    let oversized = vec![0x5a_u8; 2 * 1024 * 1024];
    let result = connection.execute(
        "INSERT INTO security_events(event_type, payload) VALUES(?1, ?2)",
        params!["oversized", oversized],
    );
    assert!(result.is_err(), "SQLite full condition accepted the event");

    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0, "failed full write left a partial journal row");

    drop(connection);
    cleanup_db(&path);
}

#[test]
fn every_supported_legacy_schema_migrates_to_current_replay_storage() {
    for version in 1..=3_i64 {
        let path = temp_db(&format!("migration-v{version}"));
        let connection = Connection::open(&path).unwrap();
        advance_fixture_to(&connection, version);
        drop(connection);

        let mut store = SqliteStore::open(&path).unwrap();
        assert_eq!(
            store
                .reserve_mutation(10_000 + version as u128, b"migration-probe")
                .unwrap(),
            MutationReservation::Started,
            "schema v{version} did not migrate to current replay storage"
        );

        drop(store);
        cleanup_db(&path);
    }
}
