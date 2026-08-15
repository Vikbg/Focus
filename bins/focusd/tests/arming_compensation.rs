use std::{future::Future, pin::pin, task::{Context, Poll, Waker}};

use focus_core::{
    Decision, PolicySet, PolicyVersion, Profile, ProfileId, RecoveryCodeHash, SessionId,
    SessionState,
};
use focus_platform::{FakeBackend, GuardKind};
use focus_storage::{FocusStore, SqliteStore, StoredActiveSession};
use focusd::arm_session;

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

fn session(id: u128) -> StoredActiveSession {
    StoredActiveSession::new(
        SessionId(id),
        SessionState::Arming,
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
fn failure_while_arming_compensates_previously_armed_guards_in_reverse_order() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = FakeBackend::default();
    backend.fail_guard(GuardKind::Browser);
    let session = session(501);

    let result = block_on_ready(arm_session(&mut store, &mut backend, &session));

    assert!(result.is_err());
    assert_eq!(backend.armed(), &[GuardKind::Process, GuardKind::Network]);
    assert_eq!(backend.disarmed(), &[GuardKind::Network, GuardKind::Process]);
    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::ProtectionFailure
    );
}

#[test]
fn verification_failure_compensates_every_armed_guard_in_reverse_order() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = FakeBackend::default();
    backend.fail_verification(GuardKind::Browser);
    let session = session(502);

    let result = block_on_ready(arm_session(&mut store, &mut backend, &session));

    assert!(result.is_err());
    assert_eq!(
        backend.armed(),
        &[
            GuardKind::Process,
            GuardKind::Network,
            GuardKind::Browser,
            GuardKind::Privilege,
        ]
    );
    assert_eq!(
        backend.disarmed(),
        &[
            GuardKind::Privilege,
            GuardKind::Browser,
            GuardKind::Network,
            GuardKind::Process,
        ]
    );
    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::ProtectionFailure
    );
}

#[test]
fn compensation_failure_still_persists_protection_failure() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = FakeBackend::default();
    backend.fail_verification(GuardKind::Browser);
    backend.fail_disarm(GuardKind::Network);
    let session = session(503);

    let result = block_on_ready(arm_session(&mut store, &mut backend, &session));

    assert!(result.is_err());
    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::ProtectionFailure
    );
    assert_eq!(
        backend.disarmed(),
        &[
            GuardKind::Privilege,
            GuardKind::Browser,
            GuardKind::Network,
            GuardKind::Process,
        ]
    );
}

#[test]
fn close_blocked_apps_failure_persists_protection_failure_without_disarming_guards() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = FakeBackend::default();
    backend.fail_close_blocked_apps();
    let session = session(504);

    let result = block_on_ready(arm_session(&mut store, &mut backend, &session));

    assert!(result.is_err());
    assert!(backend.armed().is_empty());
    assert!(backend.disarmed().is_empty());
    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::ProtectionFailure
    );
}
