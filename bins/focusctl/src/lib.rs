//! Non-authoritative command-line client for the Focus daemon.

use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
};

/// Default daemon socket used by installed Linux systems.
pub const DEFAULT_SOCKET_PATH: &str = "/run/focus/focusd.sock";

/// Sends one command to the Focus daemon through local IPC.
///
/// # Errors
///
/// Returns an I/O error when the daemon socket cannot be reached, the request
/// cannot be written, or the response cannot be read.
pub fn request_at(socket_path: &Path, command: &str) -> io::Result<String> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.write_all(command.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

/// Requests the current Focus daemon status through local IPC.
///
/// # Errors
///
/// Returns an I/O error when the daemon socket cannot be reached or the response
/// cannot be read.
pub fn status_at(socket_path: &Path) -> io::Result<String> {
    request_at(socket_path, "status")
}
