use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    path::PathBuf,
    thread,
};

fn test_socket_path() -> PathBuf {
    std::env::temp_dir().join(format!("focusctl-status-{}.sock", std::process::id()))
}

#[test]
fn status_reads_daemon_status_without_owning_security_state() {
    let socket_path = test_socket_path();
    let _ = fs::remove_file(&socket_path);
    let server_path = socket_path.clone();

    let server = thread::spawn(move || {
        let listener = UnixListener::bind(&server_path).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut request)
            .unwrap();
        assert_eq!(request, "status\n");
        stream
            .write_all(b"Focus daemon: running\nState: Idle\n")
            .unwrap();
    });

    while !socket_path.exists() {
        thread::yield_now();
    }

    let output = focusctl::status_at(&socket_path).unwrap();
    server.join().unwrap();
    let _ = fs::remove_file(&socket_path);

    assert_eq!(output, "Focus daemon: running\nState: Idle\n");
}
