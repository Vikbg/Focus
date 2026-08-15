use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use focus_platform::FakeBackend;
use focus_protocol::{MAX_FRAME_BYTES, Response, ResponseEnvelope, ResponseError};
use focus_storage::SqliteStore;
use focusd::{DaemonRuntime, DaemonService, PeerPolicy};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::oneshot,
};

fn temp_socket(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("focusd-ipc-{name}-{nonce}.sock"))
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_frame_without_newline_is_rejected_before_read_timeout() {
    let socket = temp_socket("oversized");
    let server_socket = socket.clone();
    let store = SqliteStore::open_in_memory().unwrap();
    let runtime = DaemonRuntime::new(DaemonService::new(store, FakeBackend::default()));
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
    let mut stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
    stream.write_all(&vec![b'x'; MAX_FRAME_BYTES + 1]).await.unwrap();

    let mut line = String::new();
    let response = tokio::time::timeout(
        Duration::from_millis(500),
        BufReader::new(&mut stream).read_line(&mut line),
    )
    .await;

    let _ = shutdown_tx.send(());
    server.await.unwrap();

    response.expect("oversized frame must fail before the general read timeout").unwrap();
    let envelope = ResponseEnvelope::decode(line.trim()).unwrap();
    assert_eq!(
        envelope.response(),
        Response::Error(ResponseError::InvalidRequest)
    );
}
