//! Privileged Focus daemon service primitives.

use std::{
    error::Error,
    fmt, fs,
    io::{self, BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    path::Path,
};

use focus_core::{SessionId, SessionPolicySnapshot, SessionState};
use focus_platform::{GuardKind, PlatformBackend, PlatformError};
use focus_protocol::{ClientKind, Request, RequestEnvelope, RequestId};
use focus_storage::{FocusStore, StoreError, Transition};

pub use focus_core::SessionState as DaemonState;

const REQUIRED_GUARDS: [GuardKind; 4] = [
    GuardKind::Process,
    GuardKind::Network,
    GuardKind::Browser,
    GuardKind::Privilege,
];

/// Error returned while arming a protected Focus session.
#[derive(Debug)]
pub enum ArmError {
    /// The protected store could not persist session state.
    Store(StoreError),
    /// An operating-system enforcement operation failed.
    Platform(PlatformError),
}

impl fmt::Display for ArmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "session store error: {error}"),
            Self::Platform(error) => write!(formatter, "platform enforcement error: {error:?}"),
        }
    }
}

impl Error for ArmError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Platform(_) => None,
        }
    }
}

impl From<StoreError> for ArmError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<PlatformError> for ArmError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

/// Arms one Focus session and reports Locked only after all critical guards are healthy.
///
/// The supplied policy is already a versioned immutable snapshot. It is cloned at the
/// start of arming so later profile edits cannot affect this attempt.
///
/// # Errors
///
/// Returns [`ArmError::Store`] when protected state cannot be persisted, or
/// [`ArmError::Platform`] when preflight, application closure, guard activation,
/// or health verification fails. A platform failure after Arming is persisted
/// deliberately leaves the session in Arming for recovery on restart.
pub async fn arm_session<S, B>(
    store: &mut S,
    backend: &mut B,
    session_id: SessionId,
    policy_snapshot: &SessionPolicySnapshot,
) -> Result<SessionState, ArmError>
where
    S: FocusStore,
    B: PlatformBackend,
{
    backend.preflight().await?;
    store.set_active_session(session_id, SessionState::Arming)?;

    let frozen_policy = policy_snapshot.clone();
    let _ = frozen_policy.policy();

    backend.close_blocked_apps().await?;

    for guard in REQUIRED_GUARDS {
        backend.arm_guard(guard).await?;
    }

    for guard in REQUIRED_GUARDS {
        backend.verify_guard(guard).await?;
    }

    store.persist_transition(&Transition::new(
        session_id,
        SessionState::Arming,
        SessionState::Locked,
    ))?;

    Ok(SessionState::Locked)
}

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

    format!("Focus daemon: running\nState: {}\n", state_name(state))
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
