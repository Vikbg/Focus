use std::{
    fs,
    io,
    os::unix::{
        fs::symlink,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use focus_core::SessionState;
use focusd::{PeerPolicy, bind_production_socket, serve_once_with_peer_policy};

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

fn wait_for_socket(socket: &Path) {
    for _ in 0..100 {
        if socket.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("socket did not appear");
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

    wait_for_socket(&socket);

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

    wait_for_socket(&socket);

    let response = focusctl::status_at(&socket).unwrap();
    server.join().unwrap();
    let _ = fs::remove_file(socket);

    assert_eq!(response, "Error: peer authentication failed\n");
}

#[test]
fn daemon_fails_closed_when_configured_local_uid_cannot_own_socket() {
    let socket = temp_socket("wrong-uid");
    let executable = std::env::current_exe().unwrap();
    let unexpected_uid = current_uid().wrapping_add(1);
    let policy = PeerPolicy::new(unexpected_uid, executable);

    let result = serve_once_with_peer_policy(&socket, SessionState::Idle, &policy);
    let _ = fs::remove_file(socket);

    assert!(result.is_err());
}

#[test]
fn second_daemon_cannot_replace_a_live_socket() {
    let socket = temp_socket("already-live");
    let first = UnixListener::bind(&socket).unwrap();
    let policy = PeerPolicy::new(current_uid(), std::env::current_exe().unwrap());

    let error = bind_production_socket(&socket, &policy)
        .err()
        .expect("second daemon replaced a live socket");

    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    let client = UnixStream::connect(&socket).unwrap();
    let (server, _) = first.accept().unwrap();
    drop(client);
    drop(server);
    drop(first);
    let _ = fs::remove_file(socket);
}

#[test]
fn production_bind_reclaims_a_stale_socket_after_crash() {
    let socket = temp_socket("stale");
    let stale = UnixListener::bind(&socket).unwrap();
    drop(stale);
    let policy = PeerPolicy::new(current_uid(), std::env::current_exe().unwrap());

    let listener = bind_production_socket(&socket, &policy).unwrap();
    let client = UnixStream::connect(&socket).unwrap();
    let (server, _) = listener.accept().unwrap();

    drop(client);
    drop(server);
    drop(listener);
    let _ = fs::remove_file(socket);
}

#[test]
fn production_bind_never_removes_an_existing_regular_file() {
    let socket = temp_socket("regular-file");
    let policy = PeerPolicy::new(current_uid(), std::env::current_exe().unwrap());
    fs::write(&socket, b"protected sentinel").unwrap();

    let error = bind_production_socket(&socket, &policy)
        .err()
        .expect("production bind replaced a regular file");

    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&socket).unwrap(), b"protected sentinel");
    let _ = fs::remove_file(socket);
}

#[test]
fn production_bind_never_removes_or_follows_an_existing_symlink() {
    let socket = temp_socket("symlink");
    let target = temp_socket("symlink-target");
    let policy = PeerPolicy::new(current_uid(), std::env::current_exe().unwrap());
    fs::write(&target, b"protected target").unwrap();
    symlink(&target, &socket).unwrap();

    let result = bind_production_socket(&socket, &policy);

    assert!(result.is_err());
    assert!(
        fs::symlink_metadata(&socket)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&target).unwrap(), b"protected target");
    let _ = fs::remove_file(socket);
    let _ = fs::remove_file(target);
}

#[test]
fn unauthenticated_peer_cannot_stall_daemon_before_sending_a_request() {
    let socket = temp_socket("stalled-rejected");
    let server_socket = socket.clone();
    let policy = PeerPolicy::new(current_uid(), PathBuf::from("/definitely/not-this-test"));
    let (done_tx, done_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let result = serve_once_with_peer_policy(&server_socket, SessionState::Idle, &policy);
        done_tx.send(result).unwrap();
    });

    wait_for_socket(&socket);
    let stalled_peer = UnixStream::connect(&socket).unwrap();

    let completed_without_input = done_rx.recv_timeout(Duration::from_millis(250));

    drop(stalled_peer);
    server.join().unwrap();
    let _ = fs::remove_file(socket);

    assert!(matches!(completed_without_input, Ok(Ok(()))));
}
