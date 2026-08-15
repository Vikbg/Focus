//! Privileged Focus daemon service primitives.

use std::{
    fs,
    io::{self, BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    path::Path,
};

use focus_protocol::{ClientKind, Request, RequestEnvelope, RequestId};

pub use focus_core::SessionState as DaemonState;

/// Serves one local IPC request on a Unix socket and then exits.
///
/// This helper is intentionally bounded for integration tests. The long-running
/// daemon loop will build on the same request handler.
///
/// # Errors
///
/// Returns an I/O error when the socket cannot be created or the request cannot
/// be read or answered.
pub fn serve_once(socket_path: &Path, state: DaemonState) -> io::Result<()> {
    if socket_path.exists() {
        fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    let (mut stream, _) = listener.accept()?;
    let mut request = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut request)?;

    let response = handle_line(request.trim(), state);
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn handle_line(line: &str, state: DaemonState) -> String {
    if line != "status" {
        return "Error: unsupported request\n".to_owned();
    }

    let envelope = RequestEnvelope::new(RequestId(0), ClientKind::Cli, Request::GetStatus);
    if !envelope.is_authorized() {
        return "Error: unauthorized\n".to_owned();
    }

    format!("Focus daemon: running | State: {}\n", state_name(state))
}

const fn state_name(state: DaemonState) -> &'static str {
    match state {
        DaemonState::Idle => "Idle",
        DaemonState::Preflight => "Preflight",
        DaemonState::Arming => "Arming",
        DaemonState::Locked => "Locked",
        DaemonState::EmergencyPending => "EmergencyPending",
        DaemonState::EmergencyAuthorized => "EmergencyAuthorized",
        DaemonState::Ending => "Ending",
        DaemonState::Recovering => "Recovering",
        DaemonState::ProtectionFailure => "ProtectionFailure",
    }
}
