use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use focus_platform::FakeBackend;
use focus_protocol::{
    ClientKind, Request, RequestEnvelope, RequestId, Response, ResponseEnvelope, ResponseError,
};
use focus_storage::SqliteStore;
use focusd::{DaemonRuntime, DaemonService, PeerPolicy};
use tokio::sync::oneshot;

fn temp_socket(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("focusd-runtime-{name}-{nonce}.sock"))
}

async fn wait_for_socket(socket: &Path) {
    for _ in 0..100 {
        if socket.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("socket did not appear");
}

fn send_request(socket: &Path, request_id: RequestId, request: Request) -> Response {
    let envelope = RequestEnvelope::new(request_id, ClientKind::Cli, request);
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.write_all(envelope.encode().as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();

    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    let response = ResponseEnvelope::decode(line.trim()).unwrap();
    assert!(response.is_compatible());
    assert_eq!(response.request_id(), request_id);
    response.response()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_authenticated_peer_does_not_block_second_status_connection() {
    let socket = temp_socket("concurrent");
    let server_socket = socket.clone();
    let status_socket = socket.clone();
    let store = SqliteStore::open_in_memory().unwrap();
    let service = DaemonService::new(store, FakeBackend::default());
    let runtime = DaemonRuntime::new(service);
    let policy = PeerPolicy::new(
        nix::unistd::geteuid().as_raw(),
        std::env::current_exe().unwrap(),
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        runtime
            .serve_until(&server_socket, &policy, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    wait_for_socket(&socket).await;
    let stalled_peer = tokio::net::UnixStream::connect(&socket).await.unwrap();

    let response = tokio::time::timeout(
        Duration::from_millis(500),
        tokio::task::spawn_blocking(move || focusctl::status_at(&status_socket)),
    )
    .await
    .expect("second authenticated connection must not wait for the stalled first peer")
    .unwrap()
    .unwrap();

    assert_eq!(response, "Focus daemon: running\nState: Idle\n");

    drop(stalled_peer);
    let _ = shutdown_tx.send(());
    server.await.unwrap();
    assert!(!socket.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conflicting_concurrent_mutations_with_same_request_id_have_one_winner() {
    let socket = temp_socket("mutation-conflict");
    let server_socket = socket.clone();
    let store = SqliteStore::open_in_memory().unwrap();
    let service = DaemonService::new(store, FakeBackend::default());
    let runtime = DaemonRuntime::new(service);
    let policy = PeerPolicy::new(
        nix::unistd::geteuid().as_raw(),
        std::env::current_exe().unwrap(),
    );
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        runtime
            .serve_until(&server_socket, &policy, async {
                let _ = shutdown_rx.await;
            })
            .await
            .unwrap();
    });

    wait_for_socket(&socket).await;
    let request_id = RequestId(0x5eed);
    let up_socket = socket.clone();
    let down_socket = socket.clone();

    let (up, down) = tokio::join!(
        tokio::task::spawn_blocking(move || {
            send_request(&up_socket, request_id, Request::VpnUp { id: 17 })
        }),
        tokio::task::spawn_blocking(move || {
            send_request(&down_socket, request_id, Request::VpnDown { id: 17 })
        })
    );
    let responses = [up.unwrap(), down.unwrap()];

    let success_count = responses
        .iter()
        .filter(|response| {
            matches!(
                response,
                Response::VpnUpRequested(17) | Response::VpnDownRequested(17)
            )
        })
        .count();
    let conflict_count = responses
        .iter()
        .filter(|response| **response == Response::Error(ResponseError::InvalidRequest))
        .count();
    assert_eq!(success_count, 1);
    assert_eq!(conflict_count, 1);

    let (winning_request, winning_response) = if responses.contains(&Response::VpnUpRequested(17)) {
        (Request::VpnUp { id: 17 }, Response::VpnUpRequested(17))
    } else {
        (Request::VpnDown { id: 17 }, Response::VpnDownRequested(17))
    };
    let replay_socket = socket.clone();
    let replay = tokio::task::spawn_blocking(move || {
        send_request(&replay_socket, request_id, winning_request)
    })
    .await
    .unwrap();
    assert_eq!(replay, winning_response);

    let _ = shutdown_tx.send(());
    server.await.unwrap();
    assert!(!socket.exists());
}
