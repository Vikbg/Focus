use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use focus_platform::FakeBackend;
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
