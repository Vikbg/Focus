use std::{
    fs,
    path::PathBuf,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use focus_core::SessionState;

fn temp_socket(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("focusd-{name}-{nonce}.sock"))
}

fn round_trip(command: &str) -> String {
    let socket = temp_socket("cli");
    let socket_for_server = socket.clone();
    let server = thread::spawn(move || {
        focusd::serve_once(&socket_for_server, SessionState::Locked).unwrap();
    });

    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let response = focusctl::request_at(&socket, command).unwrap();
    server.join().unwrap();
    let _ = fs::remove_file(socket);
    response
}

#[test]
fn daemon_handles_read_only_cli_commands() {
    assert_eq!(round_trip("session"), "Session state: Locked\n");
    assert_eq!(round_trip("doctor"), "Doctor: daemon reachable\n");
    assert_eq!(round_trip("vpn list"), "VPNs: none configured\n");
}

#[test]
fn daemon_validates_vpn_command_ids() {
    assert_eq!(round_trip("vpn up 42"), "VPN up requested: 42\n");
    assert_eq!(round_trip("vpn down 42"), "VPN down requested: 42\n");
    assert_eq!(round_trip("vpn up nope"), "Error: invalid VPN id\n");
}
