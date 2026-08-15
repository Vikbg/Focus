use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_core::{
    Decision, PolicySet, PolicyVersion, Profile, ProfileId, RecoveryCodeHash, SessionId,
    SessionState,
};
use focus_platform::{FakeBackend, GuardKind, PlatformError};
use focus_storage::{FocusStore, SqliteStore, StoredActiveSession};
use focusd::{ArmError, arm_session};

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
        .snapshot(),
        1_000,
        2_000,
        RecoveryCodeHash::from_code(CODE),
    )
}

#[test]
fn network_guard_failure_prevents_locked_state() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = FakeBackend::default();
    backend.fail_guard(GuardKind::Network);
    let session = stored_session(42, SessionState::Arming);

    let error = block_on_ready(arm_session(&mut store, &mut backend, &session)).unwrap_err();

    assert!(matches!(
        error,
        ArmError::ArmingFailed {
            source: PlatformError::GuardFailed(GuardKind::Network),
            ..
        }
    ));
    assert!(
        error
            .compensation_report()
            .unwrap()
            .remaining_guards()
            .is_empty()
    );

    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.id(), session.id());
    assert_eq!(active.state(), SessionState::ProtectionFailure);
    assert_ne!(active.state(), SessionState::Locked);
    assert_eq!(active.policy_sha256(), session.policy_sha256());
    assert_eq!(active.policy_snapshot().profile_version(), PolicyVersion(3));
}

#[test]
fn arming_refuses_to_replace_an_existing_active_session() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let existing = stored_session(100, SessionState::Locked);
    store.set_active_session(&existing).unwrap();
    let mut backend = FakeBackend::default();
    let new_session = stored_session(101, SessionState::Arming);

    let result = block_on_ready(arm_session(&mut store, &mut backend, &new_session));

    assert!(matches!(result, Err(ArmError::ActiveSessionExists)));
    let active = store.active_session().unwrap().unwrap();
    assert_eq!(active.id(), existing.id());
    assert_eq!(active.state(), SessionState::Locked);
    assert_eq!(active.policy_sha256(), existing.policy_sha256());
}
