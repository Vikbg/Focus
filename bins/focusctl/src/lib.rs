//! Non-authoritative command-line client for the Focus daemon.

use std::{
    io::{self, BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use focus_protocol::{
    ClientKind, ProtocolState, Request, RequestEnvelope, RequestId, Response, ResponseEnvelope,
    ResponseError,
};

/// Default daemon socket used by installed Linux systems.
pub const DEFAULT_SOCKET_PATH: &str = "/run/focus/focusd.sock";

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

fn next_request_id() -> RequestId {
    let counter = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    RequestId((u128::from(std::process::id()) << 64) | u128::from(counter))
}

fn parse_command(command: &str) -> io::Result<Request> {
    match command {
        "status" => Ok(Request::GetStatus),
        "session" => Ok(Request::GetSession),
        "doctor" => Ok(Request::Doctor),
        "vpn list" => Ok(Request::GetVpnList),
        _ => {
            let mut parts = command.split_whitespace();
            let vpn = parts.next();
            let action = parts.next();
            let id = parts.next();
            if parts.next().is_some() || vpn != Some("vpn") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported focusctl command",
                ));
            }
            let id = id
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing VPN id"))?
                .parse::<u128>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid VPN id"))?;
            match action {
                Some("up") => Ok(Request::VpnUp { id }),
                Some("down") => Ok(Request::VpnDown { id }),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported focusctl command",
                )),
            }
        }
    }
}

fn state_name(state: ProtocolState) -> &'static str {
    match state {
        ProtocolState::Idle => "Idle",
        ProtocolState::Preflight => "Preflight",
        ProtocolState::Arming => "Arming",
        ProtocolState::Locked => "Locked",
        ProtocolState::EmergencyPending => "EmergencyPending",
        ProtocolState::EmergencyAuthorized => "EmergencyAuthorized",
        ProtocolState::Ending => "Ending",
        ProtocolState::Recovering => "Recovering",
        ProtocolState::ProtectionFailure => "ProtectionFailure",
    }
}

fn render_response(response: Response) -> String {
    match response {
        Response::Status(state) => {
            format!("Focus daemon: running\nState: {}\n", state_name(state))
        }
        Response::Session(state) => format!("Session state: {}\n", state_name(state)),
        Response::DoctorReachable => "Doctor: daemon reachable\n".to_owned(),
        Response::VpnListEmpty => "VPNs: none configured\n".to_owned(),
        Response::VpnUpRequested(id) => format!("VPN up requested: {id}\n"),
        Response::VpnDownRequested(id) => format!("VPN down requested: {id}\n"),
        Response::Error(error) => format!("Error: {}\n", response_error_name(error)),
    }
}

const fn response_error_name(error: ResponseError) -> &'static str {
    match error {
        ResponseError::Unauthorized => "unauthorized",
        ResponseError::UnsupportedRequest => "unsupported request",
        ResponseError::InvalidRequest => "invalid request",
        ResponseError::UnsupportedProtocolVersion => "unsupported protocol version",
        ResponseError::PeerAuthenticationFailed => "peer authentication failed",
        ResponseError::RequestInProgress => "request is already in progress",
        ResponseError::InternalFailure => "internal daemon failure",
    }
}

/// Sends one command to the Focus daemon through typed local IPC.
///
/// # Errors
///
/// Returns an I/O error when the command is unsupported, the daemon socket cannot
/// be reached, or the response is malformed, incompatible, or mismatched.
pub fn request_at(socket_path: &Path, command: &str) -> io::Result<String> {
    let request = parse_command(command)?;
    let request_id = next_request_id();
    let envelope = RequestEnvelope::new(request_id, ClientKind::Cli, request);

    let mut stream = UnixStream::connect(socket_path)?;
    stream.write_all(envelope.encode().as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;

    let mut response_line = String::new();
    BufReader::new(stream).read_line(&mut response_line)?;
    let response = ResponseEnvelope::decode(response_line.trim()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid daemon response: {error}"),
        )
    })?;

    if !response.is_compatible() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "daemon protocol version mismatch",
        ));
    }

    let response_payload = response.response();
    let preauth_rejection = response.request_id() == RequestId(0)
        && response_payload == Response::Error(ResponseError::PeerAuthenticationFailed);
    if response.request_id() != request_id && !preauth_rejection {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "daemon response request id mismatch",
        ));
    }

    Ok(render_response(response_payload))
}

/// Requests the current Focus daemon status through local IPC.
///
/// # Errors
///
/// Returns an I/O error when the daemon socket cannot be reached or the response
/// cannot be validated.
pub fn status_at(socket_path: &Path) -> io::Result<String> {
    request_at(socket_path, "status")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_preserves_all_os_entropy_bits() {
        let entropy = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff,
        ];

        assert_eq!(
            request_id_from_entropy(entropy),
            RequestId(u128::from_ne_bytes(entropy))
        );
    }
}
