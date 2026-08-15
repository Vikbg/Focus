use std::sync::{Arc, RwLock};

use focus_core::{EmergencyDecision, Schedule, SessionState};
use focus_platform::PlatformBackend;
use focus_protocol::{
    ReplayPolicy, Request, RequestId, Response, ResponseEnvelope, ResponseError,
};
use focus_storage::{FocusStore, MutationReservation};

use crate::{
    LinuxEmergencyError, RecoveryError, begin_linux_emergency_request,
    evaluate_linux_emergency_unlock, protocol_state, recover_session, response_for,
};

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
/// All security mutations are serialized through this object. Read-only consumers
/// receive only the immutable snapshot published after authoritative state changes.
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
    /// At-most-once requests reserve their request identifier in protected storage before
    /// any mutation executes. A completed duplicate replays its stored response, while an
    /// interrupted request remains `InProgress` and is never executed a second time.
    pub fn handle(&mut self, request_id: RequestId, request: Request) -> Response {
        if request.replay_policy() == ReplayPolicy::Repeatable {
            return response_for(request, self.state);
        }

        let fingerprint = request.replay_fingerprint();
        let reservation = match self.store.reserve_mutation(request_id.0, &fingerprint) {
            Ok(reservation) => reservation,
            Err(_) => return Response::Error(ResponseError::InternalFailure),
        };

        match reservation {
            MutationReservation::Conflict => Response::Error(ResponseError::InvalidRequest),
            MutationReservation::InProgress => Response::Error(ResponseError::RequestInProgress),
            MutationReservation::Completed(response) => replay_response(request_id, &response),
            MutationReservation::Started => {
                let response = self.execute_mutation(request);
                let encoded = ResponseEnvelope::new(request_id, response).encode();
                if self
                    .store
                    .complete_mutation(request_id.0, encoded.as_bytes())
                    .is_err()
                {
                    return Response::Error(ResponseError::InternalFailure);
                }
                response
            }
        }
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

    fn execute_mutation(&mut self, request: Request) -> Response {
        match request {
            Request::RequestEmergencyUnlock(payload) => {
                match begin_linux_emergency_request(&mut self.store, &payload.reason) {
                    Ok(_) => {
                        self.publish_state(SessionState::EmergencyPending);
                        Response::Session(protocol_state(SessionState::EmergencyPending))
                    }
                    Err(error) => map_emergency_error(error),
                }
            }
            Request::SubmitEmergencyCode(payload) => self.submit_emergency_code(&payload.code),
            other => response_for(other, self.state),
        }
    }

    fn submit_emergency_code(&mut self, code: &str) -> Response {
        let mut request = match self.store.emergency_request() {
            Ok(Some(request)) => request,
            Ok(None) => return Response::Error(ResponseError::InvalidRequest),
            Err(_) => return Response::Error(ResponseError::InternalFailure),
        };

        let evaluation = match evaluate_linux_emergency_unlock(&mut self.store, &mut request, code)
        {
            Ok(evaluation) => evaluation,
            Err(error) => return map_emergency_error(error),
        };

        if evaluation.decision() == EmergencyDecision::InvalidCode {
            return Response::Error(ResponseError::InvalidRequest);
        }

        let state = match self.store.active_session() {
            Ok(Some(active)) => active.state(),
            Ok(None) => SessionState::Idle,
            Err(_) => return Response::Error(ResponseError::InternalFailure),
        };
        self.publish_state(state);
        Response::Session(protocol_state(state))
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

fn replay_response(request_id: RequestId, encoded: &[u8]) -> Response {
    let Ok(encoded) = std::str::from_utf8(encoded) else {
        return Response::Error(ResponseError::InternalFailure);
    };
    let Ok(envelope) = ResponseEnvelope::decode(encoded) else {
        return Response::Error(ResponseError::InternalFailure);
    };
    if envelope.request_id() != request_id || !envelope.is_compatible() {
        return Response::Error(ResponseError::InternalFailure);
    }
    envelope.response()
}

fn map_emergency_error(error: LinuxEmergencyError) -> Response {
    match error {
        LinuxEmergencyError::Domain(_)
        | LinuxEmergencyError::NoActiveSession
        | LinuxEmergencyError::InvalidSessionState(_) => {
            Response::Error(ResponseError::InvalidRequest)
        }
        LinuxEmergencyError::Clock(_)
        | LinuxEmergencyError::Store(_)
        | LinuxEmergencyError::Transition(_)
        | LinuxEmergencyError::Evaluation(_) => Response::Error(ResponseError::InternalFailure),
    }
}
