use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_core::{SessionId, SessionState};
use focus_platform::{FakeBackend, GuardKind};
use focus_storage::{FocusStore, SqliteStore};
use focusd::recover_session;

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("fake backend futures must resolve immediately"),
    }
}

#[test]
fn restart_from_arming_recovers_to_locked_when_guards_are_healthy() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = FakeBackend::default();
    let session_id = SessionId(84);
    store
        .set_active_session(session_id, SessionState::Arming)
        .unwrap();

    let state = block_on_ready(recover_session(&mut store, &mut backend)).unwrap();

    assert_eq!(state, SessionState::Locked);
    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::Locked
    );
    assert_eq!(store.transition_count().unwrap(), 2);
}

#[test]
fn restart_from_arming_enters_protection_failure_when_guard_reapply_fails() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = FakeBackend::default();
    backend.fail_guard(GuardKind::Network);
    let session_id = SessionId(85);
    store
        .set_active_session(session_id, SessionState::Arming)
        .unwrap();

    let state = block_on_ready(recover_session(&mut store, &mut backend)).unwrap();

    assert_eq!(state, SessionState::ProtectionFailure);
    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::ProtectionFailure
    );
    assert_eq!(store.transition_count().unwrap(), 2);
}
