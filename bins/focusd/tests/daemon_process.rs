use std::{
    fs,
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn temp_path(name: &str, extension: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("focusd-{name}-{nonce}.{extension}"))
}

#[test]
fn focusd_binary_stays_running_and_serves_authenticated_status() {
    let socket = temp_path("process", "sock");
    let database = temp_path("process", "db");
    let current_exe = std::env::current_exe().unwrap();
    let uid = nix::unistd::geteuid().as_raw().to_string();

    let mut child = Command::new(env!("CARGO_BIN_EXE_focusd"))
        .env("FOCUS_SOCKET_PATH", &socket)
        .env("FOCUS_DB_PATH", &database)
        .env("FOCUS_ALLOWED_UID", uid)
        .env("FOCUS_CLI_PATH", current_exe)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let stderr = child
                .stderr
                .take()
                .map(|stderr| std::io::read_to_string(stderr).unwrap())
                .unwrap_or_default();
            panic!("focusd exited early with {status}: {stderr}");
        }
        thread::sleep(Duration::from_millis(10));
    }

    assert!(socket.exists(), "focusd did not create its socket");
    assert_eq!(
        focusctl::status_at(&socket).unwrap(),
        "Focus daemon: running\nState: Idle\n"
    );
    assert!(child.try_wait().unwrap().is_none());

    child.kill().unwrap();
    child.wait().unwrap();
    let _ = fs::remove_file(socket);
    let _ = fs::remove_file(database);
}
