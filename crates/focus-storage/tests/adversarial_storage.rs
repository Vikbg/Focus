use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use focus_storage::{FocusStore, SecurityEvent, SqliteStore};
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

    assert!(
        failed_closed,
        "read-only database accepted a security write"
    );
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
