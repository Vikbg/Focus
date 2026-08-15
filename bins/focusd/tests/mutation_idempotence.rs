use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use focus_core::{
    Decision, PolicySet, PolicyVersion, Profile, ProfileId, RecoveryCodeHash, SessionId,
    SessionState,
};
use focus_platform::FakeBackend;
use focus_protocol::{
    EmergencyRequestPayload, ProtocolState, Request, RequestId, Response, ResponseError,
};
use focus_storage::{FocusStore, MutationReservation, SqliteStore, StoredActiveSession};
use focusd::DaemonService;

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";

fn temp_database() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("focus-service-replay-{nonce}.db"))
}

fn locked_session() -> StoredActiveSession {
    StoredActiveSession::new(
        SessionId(801),
        SessionState::Locked,
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

fn emergency(reason: &str) -> Request {
    Request::RequestEmergencyUnlock(EmergencyRequestPayload {
        reason: reason.to_owned(),
    })
}

#[tokio::test]
async fn duplicate_mutation_replays_completed_response_across_restart() {
    let path = temp_database();
    {
        let mut store = SqliteStore::open(&path).unwrap();
        store.set_active_session(&locked_session()).unwrap();
        let mut service = DaemonService::new(store, FakeBackend::default());
        assert_eq!(service.recover().await.unwrap(), SessionState::Locked);

        let first = service.handle(RequestId(77), emergency("Need to leave now"));
        assert_eq!(first, Response::Session(ProtocolState::EmergencyPending));
        assert_eq!(
            service.handle(RequestId(77), emergency("Need to leave now")),
            first
        );
    }

    {
        let store = SqliteStore::open(&path).unwrap();
        let mut restarted = DaemonService::new(store, FakeBackend::default());
        assert_eq!(
            restarted.recover().await.unwrap(),
            SessionState::EmergencyPending
        );
        assert_eq!(
            restarted.handle(RequestId(77), emergency("Need to leave now")),
            Response::Session(ProtocolState::EmergencyPending)
        );
    }

    let _ = fs::remove_file(path);
}

#[tokio::test]
async fn reused_request_id_with_different_mutation_payload_is_rejected() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store.set_active_session(&locked_session()).unwrap();
    let mut service = DaemonService::new(store, FakeBackend::default());
    assert_eq!(service.recover().await.unwrap(), SessionState::Locked);

    assert_eq!(
        service.handle(RequestId(88), emergency("First reason")),
        Response::Session(ProtocolState::EmergencyPending)
    );
    assert_eq!(
        service.handle(RequestId(88), emergency("Different reason")),
        Response::Error(ResponseError::InvalidRequest)
    );
}

#[tokio::test]
async fn interrupted_mutation_reservation_is_never_reexecuted_after_restart() {
    let path = temp_database();
    let request = emergency("Reserved before crash");
    let fingerprint = request.replay_fingerprint();

    {
        let mut store = SqliteStore::open(&path).unwrap();
        store.set_active_session(&locked_session()).unwrap();
        assert_eq!(
            store.reserve_mutation(99, &fingerprint).unwrap(),
            MutationReservation::Started
        );
    }

    {
        let store = SqliteStore::open(&path).unwrap();
        let mut restarted = DaemonService::new(store, FakeBackend::default());
        assert_eq!(restarted.recover().await.unwrap(), SessionState::Locked);
        assert_eq!(
            restarted.handle(RequestId(99), request),
            Response::Error(ResponseError::RequestInProgress)
        );
        assert_eq!(restarted.state(), SessionState::Locked);
    }

    let _ = fs::remove_file(path);
}
