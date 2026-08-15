use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn temp_socket(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("focusctl-{name}-{nonce}.sock"))
}

fn round_trip(command: &str) -> String {
    let socket = temp_socket("command");
    let (ready_tx, ready_rx) = mpsc::channel();
    let socket_for_server = socket.clone();

    let server = thread::spawn(move || {
        let listener = UnixListener::bind(&socket_for_server).unwrap();
        ready_tx.send(()).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        stream.write_all(b"ok\n").unwrap();
        line
    });

    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let response = focusctl::request_at(Path::new(&socket), command).unwrap();
    let received = server.join().unwrap();
    let _ = fs::remove_file(socket);

    assert_eq!(received, format!("{command}\n"));
    response
}

#[test]
fn supported_commands_are_forwarded_without_local_security_state() {
    for command in [
        "status",
        "session",
        "doctor",
        "vpn list",
        "vpn up 42",
        "vpn down 42",
    ] {
        assert_eq!(round_trip(command), "ok\n");
    }
}
