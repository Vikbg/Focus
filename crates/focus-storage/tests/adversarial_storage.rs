use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use focus_storage::SqliteStore;

fn temp_database(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("focus-{name}-{nonce}.db"))
}

#[test]
fn sqlite_corruption_fails_closed() {
    let path = temp_database("corrupt");
    fs::write(&path, b"not a sqlite database").unwrap();

    let result = SqliteStore::open(&path);
    let _ = fs::remove_file(&path);

    assert!(result.is_err());
}
