use std::{
    error::Error,
    fmt, fs, io,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

use focus_core::{
    EmergencyClockEvent, EmergencyClockSample, EmergencyDecision, EmergencyEvaluation,
    EmergencyRequest, ProcessEnforcementPlan, SessionEvent, SessionMachine, SessionState,
    TransitionContext, TransitionError,
};
use focus_platform::{GuardKind, PlatformBackend, PlatformError};
use focus_protocol::{
    ClientKind, EmergencyCodePayload, EmergencyRequestPayload, ProtocolState, Request,
    RequestEnvelope, RequestId, Response, ResponseEnvelope, ResponseError,
};
use focus_storage::{FocusStore, SecurityEvent, StoreError, StoredActiveSession};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

pub mod runtime;
pub mod service;

const NON_PROCESS_GUARDS: [GuardKind; 3] = [
    GuardKind::Network,
    GuardKind::Browser,
    GuardKind::Privilege,
];
const EMERGENCY_REQUEST_EVENT: &str = "emergency_request";
const EMERGENCY_AUTHORIZED_EVENT: &str = "emergency_authorized";
const IPC_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Error returned while arming a protected Focus session.
#[derive(Debug)]
pub enum ArmError {
    ActiveSessionExists,
    MissingProcessPolicy,
    Store(StoreError),
    Platform(PlatformError),
    Transition(TransitionError),
    ArmingFailed {
        source: PlatformError,
        compensation: CompensationReport,
    },
}

impl fmt::Display for ArmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActiveSessionExists => formatter.write_str("another Focus session is active"),
            Self::MissingProcessPolicy => {
                formatter.write_str("session snapshot is missing frozen process policy")
            }
            Self::Store(error) => write!(formatter, "session store error: {error}"),
            Self::Platform(error) => write!(formatter, "platform enforcement error: {error:?}"),
            Self::Transition(error) => write!(formatter, "session transition error: {error:?}"),
            Self::ArmingFailed {
                source,
                compensation,
            } => write!(
                formatter,
                "arming failed at {source:?}; {} guard(s) remain active after compensation",
                compensation.remaining_guards.len()
            ),
        }
    }
}

impl Error for ArmError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::ActiveSessionExists
            | Self::MissingProcessPolicy
            | Self::Platform(_)
            | Self::Transition(_)
            | Self::ArmingFailed { .. } => None,
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

impl From<TransitionError> for ArmError {
    fn from(error: TransitionError) -> Self {
        Self::Transition(error)
    }
}

impl ArmError {
    /// Returns the compensation result when arming reached a platform-effect failure.
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

    async fn close_blocked_apps(
        &mut self,
        plan: &ProcessEnforcementPlan,
    ) -> Result<(), PlatformError> {
        self.backend.close_blocked_apps(plan).await
    }

    /// Arms the process guard against a frozen enforcement plan and records it for compensation.
    ///
    /// # Errors
    ///
    /// Returns the platform error without adding Process to the applied ledger when arming fails.
    pub async fn arm_process_guard(
        &mut self,
        plan: &ProcessEnforcementPlan,
    ) -> Result<(), PlatformError> {
        self.backend.arm_process_guard(plan).await?;
        self.applied.push(GuardKind::Process);
        Ok(())
    }

    async fn verify_process_guard(
        &mut self,
        expected_policy_digest: [u8; 32],
    ) -> Result<(), PlatformError> {
        self.backend
            .verify_process_guard(expected_policy_digest)
            .await
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

async fn fail_arming<S: FocusStore, B: PlatformBackend>(
    store: &mut S,
    coordinator: &mut ArmingCoordinator<'_, B>,
    session: &StoredActiveSession,
    source: PlatformError,
) -> Result<SessionState, ArmError> {
    let compensation = coordinator.compensate().await;
    let failure = SessionMachine::apply(
        SessionState::Arming,
        SessionEvent::ProtectionFailed,
        &transition_context(session),
    )?;
    store.persist_transition(session.id(), &failure)?;
    Err(ArmError::ArmingFailed {
        source,
        compensation,
    })
}

/// Persists the immutable policy snapshot, arms every platform guard, and locks the session.
///
/// If any platform step fails after the `Arming` state is persisted, all previously applied
/// guards are compensated in reverse order. A failed compensation remains visible in the returned
/// report and the persisted session still transitions to `ProtectionFailure`.
///
/// # Errors
///
/// Returns an error if another session is active, the persisted session lacks a frozen process
/// policy, protected state cannot be persisted, a state transition is invalid, or platform
/// enforcement fails.
pub async fn arm_session<S: FocusStore, B: PlatformBackend>(
    store: &mut S,
    backend: &mut B,
    session: &StoredActiveSession,
) -> Result<SessionState, ArmError> {
    if store.active_session()?.is_some() {
        return Err(ArmError::ActiveSessionExists);
    }

    let process_plan = session
        .policy_snapshot()
        .process_enforcement_plan()
        .ok_or(ArmError::MissingProcessPolicy)?;

    let transition = SessionMachine::apply(
        SessionState::Idle,
        SessionEvent::StartRequested,
        &transition_context(session),
    )?;
    if transition.to() != session.state() {
        return Err(ArmError::Transition(TransitionError::InvalidTransition {
            from: transition.from(),
            event: transition.event(),
        }));
    }

    backend.preflight().await?;
    store.set_active_session(session)?;

    let mut coordinator = ArmingCoordinator::new(backend);
    if let Err(error) = coordinator.close_blocked_apps(&process_plan).await {
        return fail_arming(store, &mut coordinator, session, error).await;
    }
    if let Err(error) = coordinator.arm_process_guard(&process_plan).await {
        return fail_arming(store, &mut coordinator, session, error).await;
    }
    for guard in NON_PROCESS_GUARDS {
        if let Err(error) = coordinator.arm_guard(guard).await {
            return fail_arming(store, &mut coordinator, session, error).await;
        }
    }
    if let Err(error) = coordinator
        .verify_process_guard(process_plan.policy_digest())
        .await
    {
        return fail_arming(store, &mut coordinator, session, error).await;
    }
    for guard in NON_PROCESS_GUARDS {
        if let Err(error) = coordinator.verify_guard(guard).await {
            return fail_arming(store, &mut coordinator, session, error).await;
        }
    }

    let locked = SessionMachine::apply(
        SessionState::Arming,
        SessionEvent::GuardsReady,
        &transition_context(session),
    )?;
    store.persist_transition(session.id(), &locked)?;
    Ok(SessionState::Locked)
}

async fn restore_all_protections<B: PlatformBackend>(
    backend: &mut B,
    process_plan: Option<&ProcessEnforcementPlan>,
) -> bool {
    let Some(process_plan) = process_plan else {
        return false;
    };
    if backend.preflight().await.is_err()
        || backend.close_blocked_apps(process_plan).await.is_err()
        || backend.arm_process_guard(process_plan).await.is_err()
    {
        return false;
    }
    for guard in NON_PROCESS_GUARDS {
        if backend.arm_guard(guard).await.is_err() {
            return false;
        }
    }
    if backend
        .verify_process_guard(process_plan.policy_digest())
        .await
        .is_err()
    {
        return false;
    }
    for guard in NON_PROCESS_GUARDS {
        if backend.verify_guard(guard).await.is_err() {
            return false;
        }
    }
    true
}

/// Reconciles one persisted active session after a daemon restart.
///
/// Persisted transient or locked states first move to `Recovering`, every protection is then
/// re-applied, and the session returns to `Locked` only when all guards verify healthy. A persisted
/// `EmergencyPending` session keeps that exact lifecycle identity while protections are re-armed,
/// instead of being collapsed into a generic recovery state. A legacy snapshot without a process
/// plan can never recover to `Locked` and instead enters `ProtectionFailure`.
///
/// # Errors
///
/// Returns an error if protected state cannot be read or the authoritative state machine rejects a
/// required recovery transition.
pub async fn recover_session<S: FocusStore, B: PlatformBackend>(
    store: &mut S,
    backend: &mut B,
) -> Result<SessionState, RecoveryError> {
    let Some(active) = store.active_session()? else {
        return Ok(SessionState::Idle);
    };

    let state = active.state();
    if state == SessionState::ProtectionFailure {
        return Ok(SessionState::ProtectionFailure);
    }
    if state == SessionState::EmergencyAuthorized {
        let ending = SessionMachine::apply(
            SessionState::EmergencyAuthorized,
            SessionEvent::EndRequested,
            &transition_context(&active),
        )?;
        store.persist_transition(active.id(), &ending)?;
        return Ok(SessionState::Ending);
    }
    if state == SessionState::Ending {
        return Ok(SessionState::Ending);
    }

    let process_plan = active.policy_snapshot().process_enforcement_plan();

    if state == SessionState::EmergencyPending {
        if restore_all_protections(backend, process_plan.as_ref()).await {
            return Ok(SessionState::EmergencyPending);
        }

        let failure = SessionMachine::apply(
            SessionState::EmergencyPending,
            SessionEvent::ProtectionFailed,
            &transition_context(&active),
        )?;
        store.persist_transition(active.id(), &failure)?;
        return Ok(SessionState::ProtectionFailure);
    }

    if state != SessionState::Recovering {
        let recovering = SessionMachine::apply(
            state,
            SessionEvent::RecoveryStarted,
            &transition_context(&active),
        )?;
        store.persist_transition(active.id(), &recovering)?;
    }

    let event = if restore_all_protections(backend, process_plan.as_ref()).await {
        SessionEvent::RecoverySucceeded
    } else {
        SessionEvent::ProtectionFailed
    };
    let next = SessionMachine::apply(
        SessionState::Recovering,
        event,
        &transition_context(&active),
    )?;
    store.persist_transition(active.id(), &next)?;
    Ok(next.to())
}

/// Creates and persists a session-bound emergency request and enters `EmergencyPending`.
///
/// # Errors
///
/// Returns an error when the active session is missing, the reason is invalid, protected state
/// cannot be persisted, or the authoritative state machine rejects the request transition.
pub fn request_emergency_unlock<S: FocusStore>(
    store: &mut S,
    reason: impl Into<String>,
    clock: EmergencyClockSample,
) -> Result<EmergencyRequest, EmergencyUnlockError> {
    let active = store
        .active_session()?
        .ok_or(EmergencyUnlockError::NoActiveSession)?;
    if active.state() != SessionState::Locked {
        return Err(EmergencyUnlockError::InvalidSessionState(active.state()));
    }

    let request = EmergencyRequest::new(active.id(), reason, clock).map_err(|_| {
        EmergencyUnlockError::InvalidSessionState(active.state())
    })?;
    let transition = SessionMachine::apply(
        active.state(),
        SessionEvent::EmergencyRequested,
        &transition_context(&active),
    )?;
    let event = SecurityEvent::new(
        EMERGENCY_REQUEST_EVENT,
        format!("session={:032x}", active.id().0).into_bytes(),
    );
    store.persist_emergency_observation(
        &request,
        Some(&event),
        Some((active.id(), &transition)),
    )?;
    Ok(request)
}

/// Evaluates a session-bound emergency request using the production Linux clock sampler.
///
/// # Errors
///
/// Returns an error if no matching request exists, the request is stale or invalid for the active
/// session, the Linux clock cannot be sampled, or protected state cannot be persisted.
pub fn authorize_emergency_unlock<S: FocusStore>(
    store: &mut S,
    recovery_code: &str,
) -> Result<EmergencyEvaluation, EmergencyUnlockError> {
    let mut request = store
        .emergency_request()?
        .ok_or(EmergencyUnlockError::NoActiveSession)?;
    let sample = focus_linux::sample_emergency_clock()
        .map_err(|_| EmergencyUnlockError::InvalidSessionState(SessionState::ProtectionFailure))?;
    let evaluation = evaluate_emergency_unlock(store, &mut request, sample, recovery_code)?;
    if evaluation.decision() == EmergencyDecision::Authorized {
        let event = SecurityEvent::new(
            EMERGENCY_AUTHORIZED_EVENT,
            format!("session={:032x}", request.session_id().0).into_bytes(),
        );
        store.append_security_event(&event)?;
    }
    Ok(evaluation)
}

/// Handles one authenticated IPC request against the authoritative daemon state.
pub fn response_for(request: &Request, state: DaemonState) -> Response {
    match request {
        Request::GetStatus | Request::GetSession => Response::Status(state.into()),
        Request::GetProfiles
        | Request::Doctor
        | Request::GetVpnList
        | Request::EnableVpn(_)
        | Request::DisableVpn(_)
        | Request::RequestEmergencyUnlock(_)
        | Request::SubmitEmergencyCode(_) => Response::Error(ResponseError::UnsupportedRequest),
        Request::StartSession(_) => Response::Error(ResponseError::UnsupportedRequest),
    }
}

/// Immutable status projection shared with concurrent read-only IPC handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonSnapshot {
    state: DaemonState,
}

impl DaemonSnapshot {
    #[must_use]
    pub const fn state(self) -> DaemonState {
        self.state
    }
}

/// Creates a production Unix listener after validating the configured desktop identity.
///
/// Existing filesystem entries are handled conservatively. A live socket fails with `AddrInUse`,
/// regular files and symbolic links fail with `AlreadyExists`, and only a Unix socket proven stale
/// by a refused connection is removed before binding.
///
/// # Errors
///
/// Returns an I/O error when the desktop identity cannot own the socket, an existing path cannot be
/// proven safe to replace, or the listener cannot be bound or secured.
pub fn bind_production_socket(path: &Path, policy: &PeerPolicy) -> io::Result<UnixListener> {
    use nix::unistd::geteuid;

    if policy.allowed_uid != geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "configured desktop uid cannot own the daemon socket",
        ));
    }
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "refusing to replace non-socket IPC path",
            ));
        }
        match UnixStream::connect(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another focusd instance is already listening",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                fs::remove_file(path)?;
            }
            Err(error) => return Err(error),
        }
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Runtime state reported by the long-lived daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonState {
    Idle,
    Arming,
    Locked,
    EmergencyPending,
    ProtectionFailure,
    Ending,
}

impl From<SessionState> for DaemonState {
    fn from(state: SessionState) -> Self {
        match state {
            SessionState::Idle => Self::Idle,
            SessionState::Arming | SessionState::Recovering => Self::Arming,
            SessionState::Locked => Self::Locked,
            SessionState::EmergencyPending | SessionState::EmergencyAuthorized => {
                Self::EmergencyPending
            }
            SessionState::ProtectionFailure => Self::ProtectionFailure,
            SessionState::Ending => Self::Ending,
        }
    }
}

impl From<DaemonState> for ProtocolState {
    fn from(state: DaemonState) -> Self {
        match state {
            DaemonState::Idle => Self::Idle,
            DaemonState::Arming => Self::Arming,
            DaemonState::Locked => Self::Locked,
            DaemonState::EmergencyPending => Self::EmergencyPending,
            DaemonState::ProtectionFailure => Self::ProtectionFailure,
            DaemonState::Ending => Self::Ending,
        }
    }
}

pub fn handle_connection(
    stream: &mut UnixStream,
    state: DaemonState,
    policy: &PeerPolicy,
) -> io::Result<()> {
    if !policy.authenticate_peer(stream) {
        let envelope = ResponseEnvelope::new(
            RequestId(0),
            Response::Error(ResponseError::PeerAuthenticationFailed),
        );
        stream.write_all(envelope.encode().as_bytes())?;
        stream.write_all(b"\n")?;
        stream.flush()?;
        return Ok(());
    }

    stream.set_read_timeout(Some(IPC_READ_TIMEOUT))?;
    let mut reader = stream.try_clone()?;
    let envelope = match read_bounded_frame(&mut reader, MAX_FRAME_BYTES) {
        Ok(frame) => match RequestEnvelope::decode(&frame) {
            Ok(envelope) => envelope,
            Err(_) => {
                let envelope = ResponseEnvelope::new(
                    RequestId(0),
                    Response::Error(ResponseError::InvalidRequest),
                );
                stream.write_all(envelope.encode().as_bytes())?;
                stream.write_all(b"\n")?;
                stream.flush()?;
                return Ok(());
            }
        },
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            let envelope = ResponseEnvelope::new(
                RequestId(0),
                Response::Error(ResponseError::InvalidRequest),
            );
            stream.write_all(envelope.encode().as_bytes())?;
            stream.write_all(b"\n")?;
            stream.flush()?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };

    let response = if !envelope.is_compatible() {
        Response::Error(ResponseError::UnsupportedProtocolVersion)
    } else if !envelope.is_authorized_as(ClientKind::Cli) {
        Response::Error(ResponseError::Unauthorized)
    } else {
        response_for(envelope.request(), state)
    };
    let reply = ResponseEnvelope::new(envelope.request_id(), response);
    stream.write_all(reply.encode().as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn read_bounded_frame(reader: &mut UnixStream, max_bytes: usize) -> io::Result<String> {
    let mut frame = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 1024];
    loop {
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "IPC peer closed before sending a full frame",
            ));
        }
        let received = &chunk[..count];
        if let Some(newline) = received.iter().position(|byte| *byte == b'\n') {
            if frame.len() + newline > max_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IPC frame exceeds maximum size",
                ));
            }
            frame.extend_from_slice(&received[..newline]);
            return String::from_utf8(frame).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "IPC frame is not valid UTF-8")
            });
        }
        if frame.len() + count > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "IPC frame exceeds maximum size",
            ));
        }
        frame.extend_from_slice(received);
    }
}
