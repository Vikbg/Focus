use super::*;

#[test]
fn sqlite_full_during_security_write_fails_without_partial_event() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let page_count: i64 = store
        .connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .unwrap();
    let configured: i64 = store
        .connection
        .query_row(
            &format!("PRAGMA max_page_count = {page_count}"),
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(configured, page_count);

    let event = SecurityEvent::new("oversized", vec![0x5a; 2 * 1024 * 1024]);

    assert!(store.append_security_event(&event).is_err());
    assert_eq!(store.security_event_count().unwrap(), 0);
}
