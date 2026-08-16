use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use focus_storage::{FocusStore, MutationReservation, SqliteStore};

fn temp_database() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("focus-mutation-replay-{nonce}.db"))
}

#[test]
fn mutation_reservation_survives_reconnect_and_restart() {
    let path = temp_database();
    let fingerprint = b"emergency-request|reason-a";

    {
        let mut store = SqliteStore::open(&path).unwrap();
        assert_eq!(
            store.reserve_mutation(42, fingerprint).unwrap(),
            MutationReservation::Started
        );
        assert_eq!(
            store.reserve_mutation(42, fingerprint).unwrap(),
            MutationReservation::InProgress
        );
        assert_eq!(
            store
                .reserve_mutation(42, b"emergency-request|reason-b")
                .unwrap(),
            MutationReservation::Conflict
        );
    }

    {
        let mut reopened = SqliteStore::open(&path).unwrap();
        assert_eq!(
            reopened.reserve_mutation(42, fingerprint).unwrap(),
            MutationReservation::InProgress
        );
        reopened
            .complete_mutation(42, b"1|42|status|Idle|-")
            .unwrap();
    }

    {
        let mut reopened = SqliteStore::open(&path).unwrap();
        assert_eq!(
            reopened.reserve_mutation(42, fingerprint).unwrap(),
            MutationReservation::Completed(b"1|42|status|Idle|-".to_vec())
        );
        assert_eq!(
            reopened
                .reserve_mutation(42, b"emergency-request|reason-b")
                .unwrap(),
            MutationReservation::Conflict
        );
    }

    let _ = fs::remove_file(path);
}

#[test]
fn completing_unknown_mutation_fails_closed() {
    let mut store = SqliteStore::open_in_memory().unwrap();

    assert!(store.complete_mutation(404, b"response").is_err());
}
