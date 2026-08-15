use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_core::{Decision, PolicySet, PolicyVersion, Profile, ProfileId, SessionId, SessionState};
use focus_platform::{FakeBackend, GuardKind, PlatformError};
use focus_storage::{FocusStore, SqliteStore};
use focusd::{ArmError, arm_session};

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("fake backend futures must resolve immediately"),
    }
}

fn policy_snapshot() -> focus_core::SessionPolicySnapshot {
    Profile::new(
        ProfileId(7),
        PolicyVersion(3),
        PolicySet::new(Decision::Allow),
    )
    .snapshot()
}

#[test]
fn network_guard_failure_prevents_locked_state() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = FakeBackend::default();
    backend.fail_guard(GuardKind::Network);
    let session_id = SessionId(42);
    let policy_snapshot = policy_snapshot();

    let result = block_on_ready(arm_session(
        &mut store,
        &mut backend,
        session_id,
        &policy_snapshot,
    ));

    assert!(matches!(
        result,
        Err(ArmError::Platform(PlatformError::GuardFailed(
            GuardKind::Network
        )))
    ));

    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.id(), session_id);
    assert_eq!(active.state(), SessionState::Arming);
    assert_ne!(active.state(), SessionState::Locked);
    assert_eq!(policy_snapshot.profile_version(), PolicyVersion(3));
}

#[test]
fn arming_refuses_to_replace_an_existing_active_session() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let existing_id = SessionId(100);
    store
        .set_active_session(existing_id, SessionState::Locked)
        .unwrap();
    let mut backend = FakeBackend::default();

    let result = block_on_ready(arm_session(
        &mut store,
        &mut backend,
        SessionId(101),
        &policy_snapshot(),
    ));

    assert!(matches!(result, Err(ArmError::ActiveSessionExists)));
    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.id(), existing_id);
    assert_eq!(active.state(), SessionState::Locked);
}
