use std::{
    fs,
    path::PathBuf,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use focus_core::SessionState;
use focusd::{PeerPolicy, serve_once_with_peer_policy};

fn temp_socket(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("focusd-peer-{name}-{nonce}.sock"))
}

fn current_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

#[test]
fn authenticated_peer_with_expected_executable_can_query_status() {
    let socket = temp_socket("allowed");
    let server_socket = socket.clone();
    let executable = std::env::current_exe().unwrap();
    let policy = PeerPolicy::new(current_uid(), executable);
    let server = thread::spawn(move || {
        serve_once_with_peer_policy(&server_socket, SessionState::Idle, &policy).unwrap();
    });

    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let response = focusctl::status_at(&socket).unwrap();
    server.join().unwrap();
    let _ = fs::remove_file(socket);

    assert_eq!(response, "Focus daemon: running\nState: Idle\n");
}

#[test]
fn peer_with_unexpected_executable_is_rejected() {
    let socket = temp_socket("rejected");
    let server_socket = socket.clone();
    let policy = PeerPolicy::new(current_uid(), PathBuf::from("/definitely/not/focusctl"));
    let server = thread::spawn(move || {
        serve_once_with_peer_policy(&server_socket, SessionState::Idle, &policy).unwrap();
    });

    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let response = focusctl::status_at(&socket).unwrap();
    server.join().unwrap();
    let _ = fs::remove_file(socket);

    assert_eq!(response, "Error: peer authentication failed\n");
}
