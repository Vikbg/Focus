use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use focus_protocol::{ClientKind, Request, RequestEnvelope, Response, ResponseEnvelope};

fn temp_socket(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("focusctl-{name}-{nonce}.sock"))
}

fn expected_request(command: &str) -> Request {
    match command {
        "status" => Request::GetStatus,
        "session" => Request::GetSession,
        "doctor" => Request::Doctor,
        "vpn list" => Request::GetVpnList,
        "vpn up 42" => Request::VpnUp { id: 42 },
        "vpn down 42" => Request::VpnDown { id: 42 },
        _ => panic!("unexpected test command"),
    }
}

fn success_response(request: Request) -> Response {
    match request {
        Request::GetStatus => Response::Status(focus_protocol::ProtocolState::Idle),
        Request::GetSession => Response::Session(focus_protocol::ProtocolState::Idle),
        Request::Doctor => Response::DoctorReachable,
        Request::GetVpnList => Response::VpnListEmpty,
        Request::VpnUp { id } => Response::VpnUpRequested(id),
        Request::VpnDown { id } => Response::VpnDownRequested(id),
        _ => panic!("unexpected test request"),
    }
}

fn round_trip(command: &str) -> RequestEnvelope {
    let socket = temp_socket("command");
    let (ready_tx, ready_rx) = mpsc::channel();
    let socket_for_server = socket.clone();
    let expected = expected_request(command);

    let server = thread::spawn(move || {
        let listener = UnixListener::bind(&socket_for_server).unwrap();
        ready_tx.send(()).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        let envelope = RequestEnvelope::decode(line.trim()).unwrap();
        let response = ResponseEnvelope::new(envelope.request_id(), success_response(expected));
        stream.write_all(response.encode().as_bytes()).unwrap();
        stream.write_all(b"\n").unwrap();
        envelope
    });

    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    focusctl::request_at(Path::new(&socket), command).unwrap();
    let received = server.join().unwrap();
    let _ = fs::remove_file(socket);

    received
}

#[test]
fn supported_commands_are_forwarded_as_typed_cli_requests() {
    for command in [
        "status",
        "session",
        "doctor",
        "vpn list",
        "vpn up 42",
        "vpn down 42",
    ] {
        let envelope = round_trip(command);
        assert_eq!(envelope.client(), ClientKind::Cli);
        assert_eq!(envelope.request(), expected_request(command));
        assert!(envelope.is_compatible());
    }
}
