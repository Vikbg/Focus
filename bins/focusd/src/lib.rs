//! Privileged Focus daemon service primitives.

mod linux_emergency;

use std::{
    error::Error,
    fmt, fs,
    io::{self, BufRead, BufReader, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::Duration,
};

use focus_core::{
    EmergencyClockEvent, EmergencyClockSample, EmergencyDecision, EmergencyEvaluation,
    EmergencyRequest, SessionId, SessionPolicySnapshot, SessionState,
};
use focus_platform::{GuardKind, PlatformBackend, PlatformError};
use focus_protocol::{
    ClientKind, ProtocolState, Request, RequestEnvelope, RequestId, Response, ResponseEnvelope,
    ResponseError,
};
use focus_storage::{FocusStore, SecurityEvent, StoreError, Transition};
use nix::{
    sys::socket::{getsockopt, sockopt::PeerCredentials},
    unistd::{Uid, chown},
};

pub use focus_core::SessionState as DaemonState;
pub use linux_emergency::{
    LinuxEmergencyError, begin_linux_emergency_request, evaluate_linux_emergency_unlock,
};

const REQUIRED_GUARDS: [GuardKind; 4] = [
    GuardKind::Process,
    GuardKind::Network,
    GuardKind::Browser,
    GuardKind::Privilege,
];
const IPC_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Error returned while arming a protected Focus session.
#[derive(Debug)]
pub enum ArmError {
    /// Another protected session is already persisted.
    ActiveSessionExists,
    /// The protected store could not persist session state.
    Store(StoreError),
    /// An operating-system enforcement operation failed.
    Platform(PlatformError),
}

impl fmt::Display for ArmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActiveSessionExists => formatter.write_str("another Focus session is active"),
            Self::Store(error) => write!(formatter, "session store error: {error}"),
            Self::Platform(error) => write!(formatter, "platform enforcement error: {error:?}"),
        }
    }
}

impl Error for ArmError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::ActiveSessionExists | Self::Platform(_) => None,
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

/// Error returned while recovering protected session state after daemon restart.
#[derive(Debug)]
pub enum RecoveryError {
    /// The protected store could not be queried or updated.
    Store(StoreError),
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "session recovery store error: {error}"),
        }
    }
}

impl Error for RecoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
        }
    }
}

impl From<StoreError> for RecoveryError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Policy used by the production Unix-socket server to authenticate CLI peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPolicy {
    allowed_uid: u32,
    cli_executable: PathBuf,
}

impl PeerPolicy {
    /// Creates a peer policy for one user and one canonical CLI executable.
    #[must_use]
    pub fn new(allowed_uid: u32, cli_executable: PathBuf) -> Self {
        Self {
            allowed_uid,
            cli_executable,
        }
    }

    fn authenticate_peer(&self, stream: &UnixStream) -> bool {
        let Ok(credentials) = getsockopt(stream, PeerCredentials) else {
            return false;
        };
        if credentials.uid() != self.allowed_uid || credentials.pid() <= 0 {
            return false;
        }

        let peer_executable = PathBuf::from(format!("/proc/{}/exe", credentials.pid()));
        let Ok(peer_executable) = fs::read_link(peer_executable) else {
            return false;
        };
        let Ok(peer_executable) = fs::canonicalize(peer_executable) else {
            return false;
        };
        let Ok(expected_executable) = fs::canonicalize(&self.cli_executable) else {
            return false;
        };

        peer_executable == expected_executable
    }
}

/// Evaluates an emergency unlock observation, persists timing evidence, and handles anomalies.
///
/// This low-level function accepts an explicit clock sample for deterministic tests and
/// platform adapters. Production Linux code should call [`evaluate_linux_emergency_unlock`].
/// Wall-clock and reboot events are journaled. A monotonic regression is treated as a
/// clock-integrity failure and moves any active protected session to `ProtectionFailure`.
///
/// # Errors
///
/// Returns a storage error if updated timing evidence, the protection transition, or a
/// security event cannot be persisted.
pub fn evaluate_emergency_unlock<S: FocusStore>(
    store: &mut S,
    request: &mut EmergencyRequest,
    clock: EmergencyClockSample,
    recovery_code: &str,
) -> Result<EmergencyEvaluation, StoreError> {
    let mut candidate = request.clone();
    let evaluation = candidate.evaluate(clock, recovery_code);

    let transition = if evaluation.decision() == EmergencyDecision::ClockIntegrityFailure {
        store.active_session()?.and_then(|active| {
            (active.state() != SessionState::ProtectionFailure).then(|| {
                Transition::new(active.id(), active.state(), SessionState::ProtectionFailure)
            })
        })
    } else {
        None
    };

    let event = if evaluation.clock_event() == EmergencyClockEvent::None {
        None
    } else {
        let event_type = match evaluation.clock_event() {
            EmergencyClockEvent::None => unreachable!(),
            EmergencyClockEvent::WallClockAnomaly => "emergency_clock_wall_anomaly",
            EmergencyClockEvent::RebootDetected => "emergency_clock_reboot",
            EmergencyClockEvent::MonotonicRegression => "emergency_clock_monotonic_regression",
        };
        let payload = format!(
            "boot_id={:032x};monotonic_nanos={};unix={}",
            clock.boot_id().0,
            clock.monotonic_nanos(),
            clock.unix_seconds()
        )
        .into_bytes();
        Some(SecurityEvent::new(event_type, payload))
    };

    store.persist_emergency_observation(&candidate, event.as_ref(), transition.as_ref())?;
    *request = candidate;
    Ok(evaluation)
}

/// Arms one Focus session and reports Locked only after all critical guards are healthy.
///
/// The supplied policy is already a versioned immutable snapshot. It is cloned at the
/// start of arming so later profile edits cannot affect this attempt.
///
/// # Errors
///
/// Returns [`ArmError::ActiveSessionExists`] when protected state already contains
/// an active session, [`ArmError::Store`] when state cannot be persisted, or
/// [`ArmError::Platform`] when platform preparation or enforcement fails.
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
    if store.active_session()?.is_some() {
        return Err(ArmError::ActiveSessionExists);
    }

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

/// Recovers a persisted protected session after daemon restart.
///
/// Persisted `Arming` and `Locked` sessions enter `Recovering` and may return to `Locked`
/// only after all protections have been reapplied and verified. An `EmergencyPending`
/// session keeps that identity while protections are reapplied, so another interruption
/// cannot lose the pending emergency state. An interrupted `Recovering` state always targets
/// `Locked`; stale emergency-request rows never select the recovery target. Any platform
/// failure advances the active session to `ProtectionFailure`.
///
/// # Errors
///
/// Returns [`RecoveryError::Store`] if protected state cannot be queried or updated.
pub async fn recover_session<S, B>(
    store: &mut S,
    backend: &mut B,
) -> Result<SessionState, RecoveryError>
where
    S: FocusStore,
    B: PlatformBackend,
{
    let Some(active) = store.active_session()? else {
        return Ok(SessionState::Idle);
    };

    let session_id = active.id();
    let state = active.state();

    if state == SessionState::EmergencyPending {
        if restore_all_protections(backend).await {
            return Ok(SessionState::EmergencyPending);
        }

        store.persist_transition(&Transition::new(
            session_id,
            SessionState::EmergencyPending,
            SessionState::ProtectionFailure,
        ))?;
        return Ok(SessionState::ProtectionFailure);
    }

    match state {
        SessionState::Arming | SessionState::Locked => {
            store.persist_transition(&Transition::new(
                session_id,
                state,
                SessionState::Recovering,
            ))?;
        }
        SessionState::Recovering => {}
        other => return Ok(other),
    }

    if restore_all_protections(backend).await {
        store.persist_transition(&Transition::new(
            session_id,
            SessionState::Recovering,
            SessionState::Locked,
        ))?;
        Ok(SessionState::Locked)
    } else {
        store.persist_transition(&Transition::new(
            session_id,
            SessionState::Recovering,
            SessionState::ProtectionFailure,
        ))?;
        Ok(SessionState::ProtectionFailure)
    }
}

async fn restore_all_protections<B: PlatformBackend>(backend: &mut B) -> bool {
    if backend.preflight().await.is_err() || backend.close_blocked_apps().await.is_err() {
        return false;
    }

    for guard in REQUIRED_GUARDS {
        if backend.arm_guard(guard).await.is_err() {
            return false;
        }
    }

    for guard in REQUIRED_GUARDS {
        if backend.verify_guard(guard).await.is_err() {
            return false;
        }
    }

    true
}

fn protocol_state(state: DaemonState) -> ProtocolState {
    match state {
        DaemonState::Idle => ProtocolState::Idle,
        DaemonState::Preflight => ProtocolState::Preflight,
        DaemonState::Arming => ProtocolState::Arming,
        DaemonState::Locked => ProtocolState::Locked,
        DaemonState::EmergencyPending => ProtocolState::EmergencyPending,
        DaemonState::EmergencyAuthorized => ProtocolState::EmergencyAuthorized,
        DaemonState::Ending => ProtocolState::Ending,
        DaemonState::Recovering => ProtocolState::Recovering,
        DaemonState::ProtectionFailure => ProtocolState::ProtectionFailure,
    }
}

fn response_for(request: Request, state: DaemonState) -> Response {
    match request {
        Request::GetStatus => Response::Status(protocol_state(state)),
        Request::GetSession => Response::Session(protocol_state(state)),
        Request::Doctor => Response::DoctorReachable,
        Request::GetVpnList => Response::VpnListEmpty,
        Request::VpnUp { id } => Response::VpnUpRequested(id),
        Request::VpnDown { id } => Response::VpnDownRequested(id),
        _ => Response::Error(ResponseError::UnsupportedRequest),
    }
}

fn write_response(
    stream: &mut UnixStream,
    request_id: RequestId,
    response: Response,
) -> io::Result<()> {
    let envelope = ResponseEnvelope::new(request_id, response);
    stream.write_all(envelope.encode().as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn read_request(stream: &UnixStream) -> io::Result<Result<RequestEnvelope, ResponseError>> {
    let mut request = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut request)?;
    match RequestEnvelope::decode(request.trim()) {
        Ok(envelope) => Ok(Ok(envelope)),
        Err(_) => Ok(Err(ResponseError::InvalidRequest)),
    }
}

fn serve_stream_as(
    stream: &mut UnixStream,
    state: DaemonState,
    authenticated_client: ClientKind,
) -> io::Result<()> {
    let envelope = match read_request(stream)? {
        Ok(envelope) => envelope,
        Err(error) => return write_response(stream, RequestId(0), Response::Error(error)),
    };

    if !envelope.is_compatible() {
        return write_response(
            stream,
            envelope.request_id(),
            Response::Error(ResponseError::UnsupportedProtocolVersion),
        );
    }
    if !envelope.is_authorized_as(authenticated_client) {
        return write_response(
            stream,
            envelope.request_id(),
            Response::Error(ResponseError::Unauthorized),
        );
    }

    write_response(
        stream,
        envelope.request_id(),
        response_for(envelope.request(), state),
    )
}

fn serve_stream_with_peer_policy(
    stream: &mut UnixStream,
    state: DaemonState,
    policy: &PeerPolicy,
) -> io::Result<()> {
    if !policy.authenticate_peer(stream) {
        return write_response(
            stream,
            RequestId(0),
            Response::Error(ResponseError::PeerAuthenticationFailed),
        );
    }

    stream.set_read_timeout(Some(IPC_READ_TIMEOUT))?;
    let envelope = match read_request(stream)? {
        Ok(envelope) => envelope,
        Err(error) => return write_response(stream, RequestId(0), Response::Error(error)),
    };

    if !envelope.is_compatible() {
        return write_response(
            stream,
            envelope.request_id(),
            Response::Error(ResponseError::UnsupportedProtocolVersion),
        );
    }
    if !envelope.is_authorized_as(ClientKind::Cli) {
        return write_response(
            stream,
            envelope.request_id(),
            Response::Error(ResponseError::Unauthorized),
        );
    }

    write_response(
        stream,
        envelope.request_id(),
        response_for(envelope.request(), state),
    )
}

fn bind_test_socket(socket_path: &Path) -> io::Result<UnixListener> {
    if socket_path.exists() {
        fs::remove_file(socket_path)?;
    }
    UnixListener::bind(socket_path)
}

fn bind_production_socket(socket_path: &Path, policy: &PeerPolicy) -> io::Result<UnixListener> {
    if socket_path.exists() {
        fs::remove_file(socket_path)?;
    }
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    chown(socket_path, Some(Uid::from_raw(policy.allowed_uid)), None).map_err(io::Error::other)?;
    Ok(listener)
}

/// Serves one authenticated CLI request for integration tests and then exits.
///
/// # Errors
///
/// Returns an I/O error when the socket cannot be created or the request cannot be served.
pub fn serve_once(socket_path: &Path, state: DaemonState) -> io::Result<()> {
    let listener = bind_test_socket(socket_path)?;
    let (mut stream, _) = listener.accept()?;
    serve_stream_as(&mut stream, state, ClientKind::Cli)
}

/// Serves one request while authenticating the real Unix peer credentials.
///
/// # Errors
///
/// Returns an I/O error when the socket cannot be created, ownership cannot be applied,
/// or the request cannot be served.
pub fn serve_once_with_peer_policy(
    socket_path: &Path,
    state: DaemonState,
    policy: &PeerPolicy,
) -> io::Result<()> {
    let listener = bind_production_socket(socket_path, policy)?;
    let (mut stream, _) = listener.accept()?;
    serve_stream_with_peer_policy(&mut stream, state, policy)
}

/// Runs the persistent production Unix-socket server.
///
/// Each connection is authenticated independently. Malformed or unauthenticated
/// clients receive an error response and do not terminate the daemon loop.
///
/// # Errors
///
/// Returns an I/O error if the listening socket cannot be created or configured.
pub fn serve_forever(
    socket_path: &Path,
    state: DaemonState,
    policy: &PeerPolicy,
) -> io::Result<()> {
    let listener = bind_production_socket(socket_path, policy)?;
    for incoming in listener.incoming() {
        let Ok(mut stream) = incoming else {
            continue;
        };
        let _ = serve_stream_with_peer_policy(&mut stream, state, policy);
    }
    Ok(())
}
