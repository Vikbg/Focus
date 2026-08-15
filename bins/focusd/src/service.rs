use std::sync::{Arc, RwLock};

use focus_core::{Schedule, SessionState};
use focus_platform::PlatformBackend;
use focus_protocol::{Request, Response};
use focus_storage::FocusStore;

use crate::{RecoveryError, recover_session, response_for};

/// Daemon-owned health summary for the currently protected session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionHealth {
    Unknown,
    Healthy,
    Failed,
}

/// Immutable read model atomically published by the authoritative daemon service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonSnapshot {
    state: SessionState,
    protection_health: ProtectionHealth,
}

impl DaemonSnapshot {
    #[must_use]
    pub const fn state(self) -> SessionState {
        self.state
    }

    #[must_use]
    pub const fn protection_health(self) -> ProtectionHealth {
        self.protection_health
    }
}

fn health_for_state(state: SessionState) -> ProtectionHealth {
    match state {
        SessionState::Locked | SessionState::EmergencyPending => ProtectionHealth::Healthy,
        SessionState::ProtectionFailure => ProtectionHealth::Failed,
        _ => ProtectionHealth::Unknown,
    }
}

/// Long-lived authority that owns protected storage and the platform backend.
///
/// All future security mutations are serialized through this object. Read-only
/// consumers receive only the immutable snapshot published after authoritative
/// state changes.
pub struct DaemonService<S, B>
where
    S: FocusStore,
    B: PlatformBackend,
{
    store: S,
    backend: B,
    state: SessionState,
    scheduler: Vec<Schedule>,
    snapshot: Arc<RwLock<DaemonSnapshot>>,
}

impl<S, B> DaemonService<S, B>
where
    S: FocusStore,
    B: PlatformBackend,
{
    #[must_use]
    pub fn new(store: S, backend: B) -> Self {
        let state = SessionState::Idle;
        Self {
            store,
            backend,
            state,
            scheduler: Vec::new(),
            snapshot: Arc::new(RwLock::new(DaemonSnapshot {
                state,
                protection_health: health_for_state(state),
            })),
        }
    }

    /// Recovers protected state using the real asynchronous platform contract.
    ///
    /// # Errors
    ///
    /// Returns the underlying recovery error when storage or lifecycle recovery fails.
    pub async fn recover(&mut self) -> Result<SessionState, RecoveryError> {
        let state = recover_session(&mut self.store, &mut self.backend).await?;
        self.publish_state(state);
        Ok(state)
    }

    /// Routes one authenticated request through the authoritative service path.
    ///
    /// State-changing payloads that are not yet representable by the P1 protocol
    /// remain unsupported until their typed request data is introduced.
    pub fn handle(&mut self, request: Request) -> Response {
        response_for(request, self.state)
    }

    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    #[must_use]
    pub fn snapshot(&self) -> DaemonSnapshot {
        *self
            .snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[must_use]
    pub fn schedule_count(&self) -> usize {
        self.scheduler.len()
    }

    pub(crate) fn snapshot_handle(&self) -> Arc<RwLock<DaemonSnapshot>> {
        Arc::clone(&self.snapshot)
    }

    fn publish_state(&mut self, state: SessionState) {
        self.state = state;
        let snapshot = DaemonSnapshot {
            state,
            protection_health: health_for_state(state),
        };
        *self
            .snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = snapshot;
    }
}
