use std::{fs, os::unix::net::UnixStream, path::PathBuf, thread, time::Duration};

use focusd::{DaemonState, serve_once};

fn test_socket_path() -> PathBuf {
    std::env::temp_dir().join(format!("focusd-status-{}.sock", std::process::id()))
}

#[test]
fn status_request_reports_running_idle_daemon() {
    let socket_path = test_socket_path();
    let _ = fs::remove_file(&socket_path);
    let server_path = socket_path.clone();

    let server = thread::spawn(move || serve_once(&server_path, DaemonState::Idle).unwrap());

    for _ in 0..50 {
        if UnixStream::connect(&socket_path).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let output = focusd::request_status(&socket_path).unwrap();
    server.join().unwrap();
    let _ = fs::remove_file(&socket_path);

    assert_eq!(output, "Focus daemon: running\nState: Idle\n");
}
