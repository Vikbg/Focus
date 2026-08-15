//! Non-authoritative command-line client for the Focus daemon.

use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
};

/// Default daemon socket used by installed Linux systems.
pub const DEFAULT_SOCKET_PATH: &str = "/run/focus/focusd.sock";

/// Requests the current Focus daemon status through local IPC.
///
/// # Errors
///
/// Returns an I/O error when the daemon socket cannot be reached or the response
/// cannot be read.
pub fn status_at(socket_path: &Path) -> io::Result<String> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.write_all(b"status\n")?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}
