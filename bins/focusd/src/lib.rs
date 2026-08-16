//! Privileged Focus daemon service primitives.

mod config;
mod linux_emergency;
mod runtime;
mod service;

pub use config::{RuntimeConfig, RuntimeConfigError};
pub use runtime::DaemonRuntime;
pub use service::{DaemonService, DaemonSnapshot, ProtectionHealth};

use std::{
    error::Error,
    fmt, fs,
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    time::Duration,
};

use focus_core::{
    EmergencyClockEvent, EmergencyClockSample, EmergencyDecision, EmergencyEvaluation,
    EmergencyRequest, SessionEvent, SessionMachine, SessionState, TransitionContext,
    TransitionError,
};
use focus_platform::{GuardKind, PlatformBackend, PlatformError};
use focus_protocol::{
    ClientKind, MAX_FRAME_BYTES, ProtocolState, Request, RequestEnvelope, RequestId, Response,
    ResponseEnvelope, ResponseError,
};
use focus_storage::{FocusStore, SecurityEvent, StoreError, StoredActiveSession};
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
    ActiveSessionExists,
    Store(StoreError),
    Transition(TransitionError),
    Platform(PlatformError),
    ArmingFailed {
        source: PlatformError,
        compensation: CompensationReport,
    },
}

impl fmt::Display for ArmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActiveSessionExists => formatter.write_str("another Focus session is active"),
            Self::Store(error) => write!(formatter, "session store error: {error}"),
            Self::Transition(error) => write!(formatter, "session transition error: {error:?}"),
            Self::Platform(error) => write!(formatter, "platform enforcement error: {error:?}"),
            Self::ArmingFailed { source, .. } => {
                write!(
                    formatter,
                    "platform enforcement failed during arming: {source:?}"
                )
            }
        }
    }
}

impl Error for ArmError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::ActiveSessionExists
            | Self::Transition(_)
            | Self::Platform(_)
            | Self::ArmingFailed { .. } => None,
        }
    }
}

impl From<StoreError> for ArmError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<TransitionError> for ArmError {
    fn from(error: TransitionError) -> Self {
        Self::Transition(error)
    }
}

impl From<PlatformError> for ArmError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

impl ArmError {
    /// Returns the compensation report for a platform failure that occurred after
    /// the active `Arming` record was persisted.
    #[must_use]
    pub const fn compensation_report(&self) -> Option<&CompensationReport> {
        match self {
            Self::ArmingFailed { compensation, .. } => Some(compensation),
            _ => None,
        }
    }
}

/// Error returned while recovering protected session state after daemon restart.
#[derive(Debug)]
pub enum RecoveryError {
    Store(StoreError),
    Transition(TransitionError),
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "session recovery store error: {error}"),
            Self::Transition(error) => {
                write!(formatter, "session recovery transition error: {error:?}")
            }
        }
    }
}

impl Error for RecoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Transition(_) => None,
        }
    }
}

impl From<StoreError> for RecoveryError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<TransitionError> for RecoveryError {
    fn from(error: TransitionError) -> Self {
        Self::Transition(error)
    }
}

/// Error returned while evaluating and atomically persisting emergency state.
#[derive(Debug)]
pub enum EmergencyUnlockError {
    Store(StoreError),
    Transition(TransitionError),
    NoActiveSession,
    SessionMismatch,
    InvalidSessionState(SessionState),
}

impl fmt::Display for EmergencyUnlockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "emergency store error: {error}"),
            Self::Transition(error) => write!(formatter, "emergency transition error: {error:?}"),
            Self::NoActiveSession => formatter.write_str("no active Focus session"),
            Self::SessionMismatch => {
                formatter.write_str("emergency request belongs to a different session")
            }
            Self::InvalidSessionState(state) => {
                write!(
                    formatter,
                    "invalid session state for emergency unlock: {state:?}"
                )
            }
        }
    }
}

impl Error for EmergencyUnlockError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Transition(_)
            | Self::NoActiveSession
            | Self::SessionMismatch
            | Self::InvalidSessionState(_) => None,
        }
    }
}

impl From<StoreError> for EmergencyUnlockError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<TransitionError> for EmergencyUnlockError {
    fn from(error: TransitionError) -> Self {
        Self::Transition(error)
    }
}

/// Policy used by the production Unix-socket server to authenticate CLI peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPolicy {
    allowed_uid: u32,
    cli_executable: PathBuf,
}

impl PeerPolicy {
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

fn transition_context(session: &StoredActiveSession) -> TransitionContext {
    TransitionContext::new(
        session.started_at_unix_ms(),
        session.minimum_end_at_unix_ms(),
    )
}

/// Evaluates an emergency unlock observation against the precommitted active-session hash.
///
/// Timing evidence, a clock-security event, and any first lifecycle transition are committed
/// atomically. On successful authorization the session first enters `EmergencyAuthorized`,
/// then advances to `Ending`. If the second transition is interrupted, restart recovery can
/// safely continue from the explicitly authorized state.
///
/// # Errors
///
/// Returns an error if the request does not belong to the active pending session, protected
/// state cannot be persisted, or the authoritative state machine rejects a required edge.
pub fn evaluate_emergency_unlock<S: FocusStore>(
    store: &mut S,
    request: &mut EmergencyRequest,
    clock: EmergencyClockSample,
    recovery_code: &str,
) -> Result<EmergencyEvaluation, EmergencyUnlockError> {
    let active = store
        .active_session()?
        .ok_or(EmergencyUnlockError::NoActiveSession)?;
    if request.session_id() != active.id() {
        return Err(EmergencyUnlockError::SessionMismatch);
    }
    if active.state() != SessionState::EmergencyPending {
        return Err(EmergencyUnlockError::InvalidSessionState(active.state()));
    }

    let context = transition_context(&active);
    let mut candidate = request.clone();
    let evaluation = candidate.evaluate(clock, active.recovery_code_hash(), recovery_code);

    let transition = match evaluation.decision() {
        EmergencyDecision::ClockIntegrityFailure => Some(SessionMachine::apply(
            active.state(),
            SessionEvent::ProtectionFailed,
            &context,
        )?),
        EmergencyDecision::Authorized => Some(SessionMachine::apply(
            active.state(),
            SessionEvent::EmergencyAuthorized,
            &context,
        )?),
        EmergencyDecision::Waiting { .. } | EmergencyDecision::InvalidCode => None,
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

    store.persist_emergency_observation(
        &candidate,
        event.as_ref(),
        transition
            .as_ref()
            .map(|validated| (active.id(), validated)),
    )?;
    *request = candidate;

    if evaluation.decision() == EmergencyDecision::Authorized {
        let ending = SessionMachine::apply(
            SessionState::EmergencyAuthorized,
            SessionEvent::EndRequested,
            &context,
        )?;
        store.persist_transition(active.id(), &ending)?;
    }

    Ok(evaluation)
}

/// Result of one best-effort rollback of platform guards applied during arming.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompensationReport {
    remaining_guards: Vec<GuardKind>,
}

impl CompensationReport {
    /// Returns guards whose removal failed and may therefore still be active.
    #[must_use]
    pub fn remaining_guards(&self) -> &[GuardKind] {
        &self.remaining_guards
    }
}

/// Orders platform guard application and tracks effects that require compensation.
pub struct ArmingCoordinator<'a, B: PlatformBackend> {
    backend: &'a mut B,
    applied: Vec<GuardKind>,
}

impl<'a, B: PlatformBackend> ArmingCoordinator<'a, B> {
    /// Creates an empty arming ledger for one platform backend.
    pub fn new(backend: &'a mut B) -> Self {
        Self {
            backend,
            applied: Vec::new(),
        }
    }

    async fn close_blocked_apps(&mut self) -> Result<(), PlatformError> {
        self.backend.close_blocked_apps().await
    }

    /// Arms one guard and records it only after the platform operation succeeds.
    ///
    /// # Errors
    ///
    /// Returns the platform error without adding the failed guard to the applied ledger.
    pub async fn arm_guard(&mut self, guard: GuardKind) -> Result<(), PlatformError> {
        self.backend.arm_guard(guard).await?;
        self.applied.push(guard);
        Ok(())
    }

    async fn verify_guard(&mut self, guard: GuardKind) -> Result<(), PlatformError> {
        self.backend.verify_guard(guard).await
    }

    /// Reverses applied guards in reverse order without double-disarming successes.
    ///
    /// Failed disarms remain in the ledger so a later retry can safely attempt them again.
    pub async fn compensate(&mut self) -> CompensationReport {
        let mut remaining = Vec::new();
        while let Some(guard) = self.applied.pop() {
            if self.backend.disarm_guard(guard).await.is_err() {
                remaining.push(guard);
            }
        }
        remaining.reverse();
        self.applied.extend(remaining.iter().copied());
        CompensationReport {
            remaining_guards: remaining,
        }
    }
}

async fn fail_arming<S, B>(
    store: &mut S,
    coordinator: &mut ArmingCoordinator<'_, B>,
    session: &StoredActiveSession,
    platform_error: PlatformError,
) -> Result<SessionState, ArmError>
where
    S: FocusStore,
    B: PlatformBackend,
{
    let compensation = coordinator.compensate().await;
    let failure = SessionMachine::apply(
        session.state(),
        SessionEvent::ArmFailed,
        &transition_context(session),
    )?;
    store.persist_transition(session.id(), &failure)?;
    Err(ArmError::ArmingFailed {
        source: platform_error,
        compensation,
    })
}

/// Arms one Focus session and reports Locked only after all critical guards are healthy.
///
/// After `Arming` is persisted, every platform failure is compensated in reverse order
/// and the session is durably advanced to `ProtectionFailure`. Compensation is best-effort:
/// a disarm failure never turns an uncertain protection state into a fail-open state.
///
/// # Errors
///
/// Returns an error if another session exists, persistence fails, the lifecycle state is
/// invalid, or a required platform enforcement operation fails.
pub async fn arm_session<S, B>(
    store: &mut S,
    backend: &mut B,
    session: &StoredActiveSession,
) -> Result<SessionState, ArmError>
where
    S: FocusStore,
    B: PlatformBackend,
{
    if store.active_session()?.is_some() {
        return Err(ArmError::ActiveSessionExists);
    }

    let transition = SessionMachine::apply(
        session.state(),
        SessionEvent::ArmSucceeded,
        &transition_context(session),
    )?;

    backend.preflight().await?;
    store.set_active_session(session)?;
    let mut coordinator = ArmingCoordinator::new(backend);

    if let Err(error) = coordinator.close_blocked_apps().await {
        return fail_arming(store, &mut coordinator, session, error).await;
    }

    for guard in REQUIRED_GUARDS {
        if let Err(error) = coordinator.arm_guard(guard).await {
            return fail_arming(store, &mut coordinator, session, error).await;
        }
    }
    for guard in REQUIRED_GUARDS {
        if let Err(error) = coordinator.verify_guard(guard).await {
            return fail_arming(store, &mut coordinator, session, error).await;
        }
    }

    store.persist_transition(session.id(), &transition)?;
    Ok(SessionState::Locked)
}

/// Recovers a persisted protected session after daemon restart.
///
/// # Errors
///
/// Returns an error if protected state cannot be queried or if persisted state is
/// inconsistent with the authoritative recovery graph.
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
    let context = transition_context(&active);

    if state == SessionState::EmergencyAuthorized {
        let ending = SessionMachine::apply(state, SessionEvent::EndRequested, &context)?;
        store.persist_transition(session_id, &ending)?;
        return Ok(SessionState::Ending);
    }

    if state == SessionState::EmergencyPending {
        if restore_all_protections(backend).await {
            return Ok(SessionState::EmergencyPending);
        }
        let failed = SessionMachine::apply(state, SessionEvent::ProtectionFailed, &context)?;
        store.persist_transition(session_id, &failed)?;
        return Ok(SessionState::ProtectionFailure);
    }

    match state {
        SessionState::Arming | SessionState::Locked => {
            let recovering = SessionMachine::apply(state, SessionEvent::RecoveryStarted, &context)?;
            store.persist_transition(session_id, &recovering)?;
        }
        SessionState::Recovering => {}
        other => return Ok(other),
    }

    let event = if restore_all_protections(backend).await {
        SessionEvent::RecoverySucceeded
    } else {
        SessionEvent::ProtectionFailed
    };
    let final_transition = SessionMachine::apply(SessionState::Recovering, event, &context)?;
    store.persist_transition(session_id, &final_transition)?;
    Ok(final_transition.to())
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

fn response_for(request: &Request, state: DaemonState) -> Response {
    match request {
        Request::GetStatus => Response::Status(protocol_state(state)),
        Request::GetSession => Response::Session(protocol_state(state)),
        Request::Doctor => Response::DoctorReachable,
        Request::GetVpnList => Response::VpnListEmpty,
        Request::VpnUp { id } => Response::VpnUpRequested(*id),
        Request::VpnDown { id } => Response::VpnDownRequested(*id),
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
    let mut frame = Vec::with_capacity(1024);
    let mut reader = BufReader::new(stream.try_clone()?).take((MAX_FRAME_BYTES + 1) as u64);
    reader.read_until(b'\n', &mut frame)?;

    if frame.len() > MAX_FRAME_BYTES || !frame.ends_with(b"\n") {
        return Ok(Err(ResponseError::InvalidRequest));
    }
    frame.pop();
    if frame.last() == Some(&b'\r') {
        frame.pop();
    }
    let Ok(request) = std::str::from_utf8(&frame) else {
        return Ok(Err(ResponseError::InvalidRequest));
    };

    match RequestEnvelope::decode(request) {
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
        response_for(&envelope.request(), state),
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
        response_for(&envelope.request(), state),
    )
}

fn bind_test_socket(socket_path: &Path) -> io::Result<UnixListener> {
    if socket_path.exists() {
        fs::remove_file(socket_path)?;
    }
    UnixListener::bind(socket_path)
}

/// Binds the production Focus IPC socket without replacing an active or non-socket path.
///
/// A stale Unix socket is reclaimed only when connecting to it reports
/// `ConnectionRefused`.
///
/// # Errors
///
/// Returns an error if the parent directory cannot be created, an existing path is not a
/// stale Unix socket, the socket cannot be bound or configured, or ownership cannot be
/// applied to the configured local UID.
pub fn bind_production_socket(socket_path: &Path, policy: &PeerPolicy) -> io::Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }

    match fs::symlink_metadata(socket_path) {
        Ok(metadata) => {
            use std::os::unix::fs::FileTypeExt;

            if !metadata.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "refusing to replace a non-socket IPC path",
                ));
            }

            match UnixStream::connect(socket_path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "Focus daemon socket is already active",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(socket_path)?;
                }
                Err(error) => return Err(error),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
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
