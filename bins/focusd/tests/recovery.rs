use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_core::{
    BootId, Decision, EmergencyClockSample, EmergencyRequest, PolicySet, PolicyVersion,
    ProcessEnforcementPlan, ProcessPolicy, Profile, ProfileId, RecoveryCodeHash, SessionId,
    SessionState,
};
use focus_platform::{FakeBackend, GuardKind, PlatformBackend, PlatformFuture};
use focus_storage::{FocusStore, SqliteStore, StoredActiveSession};
use focusd::recover_session;

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("fake backend futures must resolve immediately"),
    }
}

fn stored_session(id: u128, state: SessionState) -> StoredActiveSession {
    StoredActiveSession::new(
        SessionId(id),
        state,
        Profile::new(
            ProfileId(7),
            PolicyVersion(3),
            PolicySet::new(Decision::Allow),
        )
        .with_process_policy(ProcessPolicy::strict(Vec::new(), Vec::new()))
        .snapshot(),
        1_000,
        2_000,
        RecoveryCodeHash::from_code(CODE),
    )
}

#[derive(Default)]
struct RecordingBackend {
    preflight: usize,
    close: usize,
    arm: usize,
    verify: usize,
}

impl PlatformBackend for RecordingBackend {
    fn preflight(&mut self) -> PlatformFuture<'_, ()> {
        self.preflight += 1;
        Box::pin(async { Ok(()) })
    }

    fn close_blocked_apps<'a>(
        &'a mut self,
        _plan: &'a ProcessEnforcementPlan,
    ) -> PlatformFuture<'a, ()> {
        self.close += 1;
        Box::pin(async { Ok(()) })
    }

    fn arm_process_guard<'a>(
        &'a mut self,
        _plan: &'a ProcessEnforcementPlan,
    ) -> PlatformFuture<'a, ()> {
        self.arm += 1;
        Box::pin(async { Ok(()) })
    }

    fn verify_process_guard(
        &mut self,
        _expected_policy_digest: [u8; 32],
    ) -> PlatformFuture<'_, ()> {
        self.verify += 1;
        Box::pin(async { Ok(()) })
    }

    fn arm_guard(&mut self, _guard: GuardKind) -> PlatformFuture<'_, ()> {
        self.arm += 1;
        Box::pin(async { Ok(()) })
    }

    fn verify_guard(&mut self, _guard: GuardKind) -> PlatformFuture<'_, ()> {
        self.verify += 1;
        Box::pin(async { Ok(()) })
    }

    fn disarm_guard(&mut self, _guard: GuardKind) -> PlatformFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

fn assert_complete_recovery(backend: &RecordingBackend) {
    assert_eq!(backend.preflight, 1);
    assert_eq!(backend.close, 1);
    assert_eq!(backend.arm, 4);
    assert_eq!(backend.verify, 4);
}

#[test]
fn restart_from_arming_recovers_to_locked_when_all_steps_are_healthy() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = RecordingBackend::default();
    let session = stored_session(84, SessionState::Arming);
    store.set_active_session(&session).unwrap();

    let state = block_on_ready(recover_session(&mut store, &mut backend)).unwrap();

    assert_eq!(state, SessionState::Locked);
    assert_complete_recovery(&backend);
    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.state(), SessionState::Locked);
    assert_eq!(active.policy_sha256(), session.policy_sha256());
    assert_eq!(store.transition_count().unwrap(), 2);
}

#[test]
fn restart_from_locked_reenters_recovery_before_reporting_locked() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = RecordingBackend::default();
    let session = stored_session(86, SessionState::Locked);
    store.set_active_session(&session).unwrap();

    let state = block_on_ready(recover_session(&mut store, &mut backend)).unwrap();

    assert_eq!(state, SessionState::Locked);
    assert_complete_recovery(&backend);
    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.policy_sha256(), session.policy_sha256());
    assert_eq!(store.transition_count().unwrap(), 2);
}

#[test]
fn restart_from_emergency_pending_rearms_without_losing_pending_identity() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = RecordingBackend::default();
    let session = stored_session(87, SessionState::EmergencyPending);
    store.set_active_session(&session).unwrap();

    let state = block_on_ready(recover_session(&mut store, &mut backend)).unwrap();

    assert_eq!(state, SessionState::EmergencyPending);
    assert_complete_recovery(&backend);
    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.state(), SessionState::EmergencyPending);
    assert_eq!(active.policy_sha256(), session.policy_sha256());
    assert_eq!(store.transition_count().unwrap(), 0);
}

#[test]
fn recovering_session_ignores_stale_emergency_request_from_previous_session() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let previous_session = stored_session(87, SessionState::EmergencyPending);
    store.set_active_session(&previous_session).unwrap();
    let previous_request = EmergencyRequest::new(
        previous_session.id(),
        "Old emergency",
        EmergencyClockSample::new(BootId(1), 100, 1_000),
    )
    .unwrap();
    store.persist_emergency_request(&previous_request).unwrap();

    let session = stored_session(88, SessionState::Recovering);
    store.set_active_session(&session).unwrap();
    let mut backend = RecordingBackend::default();

    let recovered_state = block_on_ready(recover_session(&mut store, &mut backend)).unwrap();

    assert_eq!(recovered_state, SessionState::Locked);
    assert_complete_recovery(&backend);
    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.state(), SessionState::Locked);
    assert_eq!(active.policy_sha256(), session.policy_sha256());
}

#[test]
fn restart_from_arming_enters_protection_failure_when_guard_reapply_fails() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = FakeBackend::default();
    backend.fail_guard(GuardKind::Network);
    let session = stored_session(85, SessionState::Arming);
    store.set_active_session(&session).unwrap();

    let state = block_on_ready(recover_session(&mut store, &mut backend)).unwrap();

    assert_eq!(state, SessionState::ProtectionFailure);
    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.state(), SessionState::ProtectionFailure);
    assert_eq!(active.policy_sha256(), session.policy_sha256());
    assert_eq!(store.transition_count().unwrap(), 2);
}
