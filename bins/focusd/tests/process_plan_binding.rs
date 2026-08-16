use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_core::{
    Decision, ExecutableMatcher, PolicySet, PolicyVersion, ProcessEnforcementPlan, ProcessPolicy,
    ProcessRule, Profile, ProfileId, RecoveryCodeHash, SessionId, SessionPolicySnapshot,
    SessionState,
};
use focus_platform::{GuardKind, PlatformBackend, PlatformError, PlatformFuture};
use focus_storage::{FocusStore, SqliteStore, StoredActiveSession};
use focusd::{ArmError, arm_session, recover_session};

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";
const BLOCKED_DIGEST: [u8; 32] = [0x63; 32];

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("recording backend futures must resolve immediately"),
    }
}

fn process_snapshot() -> SessionPolicySnapshot {
    Profile::new(
        ProfileId(17),
        PolicyVersion(9),
        PolicySet::new(Decision::Allow),
    )
    .with_process_policy(ProcessPolicy::strict(
        vec![ProcessRule::block(ExecutableMatcher::Digest(
            BLOCKED_DIGEST,
        ))],
        vec!["/home/student/code".to_owned()],
    ))
    .snapshot()
}

fn stored_session(id: u128, state: SessionState) -> StoredActiveSession {
    StoredActiveSession::new(
        SessionId(id),
        state,
        process_snapshot(),
        1_000,
        2_000,
        RecoveryCodeHash::from_code(CODE),
    )
}

fn legacy_session(id: u128, state: SessionState) -> StoredActiveSession {
    let snapshot = SessionPolicySnapshot::restore(
        ProfileId(17),
        PolicyVersion(8),
        1,
        &[0],
    )
    .unwrap();
    assert!(snapshot.process_enforcement_plan().is_none());
    StoredActiveSession::new(
        SessionId(id),
        state,
        snapshot,
        1_000,
        2_000,
        RecoveryCodeHash::from_code(CODE),
    )
}

#[derive(Debug, Default)]
struct RecordingBackend {
    closed_with: Option<[u8; 32]>,
    process_armed_with: Option<[u8; 32]>,
    process_verified_with: Option<[u8; 32]>,
    generic_process_calls: usize,
    generic_guards: Vec<GuardKind>,
}

impl RecordingBackend {
    fn record_generic(&mut self, guard: GuardKind) {
        if guard == GuardKind::Process {
            self.generic_process_calls += 1;
        } else {
            self.generic_guards.push(guard);
        }
    }
}

impl PlatformBackend for RecordingBackend {
    fn close_blocked_apps<'a>(
        &'a mut self,
        plan: &'a ProcessEnforcementPlan,
    ) -> PlatformFuture<'a, ()> {
        self.closed_with = Some(plan.policy_digest());
        Box::pin(async { Ok(()) })
    }

    fn arm_process_guard<'a>(
        &'a mut self,
        plan: &'a ProcessEnforcementPlan,
    ) -> PlatformFuture<'a, ()> {
        self.process_armed_with = Some(plan.policy_digest());
        Box::pin(async { Ok(()) })
    }

    fn verify_process_guard(
        &mut self,
        expected_policy_digest: [u8; 32],
    ) -> PlatformFuture<'_, ()> {
        self.process_verified_with = Some(expected_policy_digest);
        Box::pin(async { Ok(()) })
    }

    fn arm_guard(&mut self, guard: GuardKind) -> PlatformFuture<'_, ()> {
        self.record_generic(guard);
        Box::pin(async { Ok(()) })
    }

    fn verify_guard(&mut self, guard: GuardKind) -> PlatformFuture<'_, ()> {
        self.record_generic(guard);
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn arming_binds_every_process_operation_to_the_frozen_snapshot_digest() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = RecordingBackend::default();
    let session = stored_session(500, SessionState::Arming);
    let expected_digest = session.policy_sha256();

    let state = block_on_ready(arm_session(&mut store, &mut backend, &session)).unwrap();

    assert_eq!(state, SessionState::Locked);
    assert_eq!(backend.closed_with, Some(expected_digest));
    assert_eq!(backend.process_armed_with, Some(expected_digest));
    assert_eq!(backend.process_verified_with, Some(expected_digest));
    assert_eq!(backend.generic_process_calls, 0);
}

#[test]
fn recovery_reconstructs_the_same_process_plan_from_protected_storage() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session = stored_session(501, SessionState::Locked);
    let expected_digest = session.policy_sha256();
    store.set_active_session(&session).unwrap();
    let mut backend = RecordingBackend::default();

    let state = block_on_ready(recover_session(&mut store, &mut backend)).unwrap();

    assert_eq!(state, SessionState::Locked);
    assert_eq!(backend.closed_with, Some(expected_digest));
    assert_eq!(backend.process_armed_with, Some(expected_digest));
    assert_eq!(backend.process_verified_with, Some(expected_digest));
    assert_eq!(backend.generic_process_calls, 0);
}

#[test]
fn new_arming_rejects_a_snapshot_without_process_policy_before_platform_effects() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = RecordingBackend::default();
    let session = legacy_session(502, SessionState::Arming);

    let result = block_on_ready(arm_session(&mut store, &mut backend, &session));

    assert!(matches!(result, Err(ArmError::MissingProcessPolicy)));
    assert!(store.active_session().unwrap().is_none());
    assert!(backend.closed_with.is_none());
    assert!(backend.process_armed_with.is_none());
    assert!(backend.process_verified_with.is_none());
    assert_eq!(backend.generic_process_calls, 0);
    assert!(backend.generic_guards.is_empty());
}

#[test]
fn legacy_locked_session_recovers_to_protection_failure_instead_of_locked() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let session = legacy_session(503, SessionState::Locked);
    store.set_active_session(&session).unwrap();
    let mut backend = RecordingBackend::default();

    let state = block_on_ready(recover_session(&mut store, &mut backend)).unwrap();

    assert_eq!(state, SessionState::ProtectionFailure);
    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::ProtectionFailure
    );
    assert!(backend.closed_with.is_none());
    assert!(backend.process_armed_with.is_none());
    assert!(backend.process_verified_with.is_none());
    assert_eq!(backend.generic_process_calls, 0);
}
