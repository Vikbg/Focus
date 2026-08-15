use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_core::{SessionId, SessionState};
use focus_platform::{FakeBackend, GuardKind, PlatformBackend, PlatformFuture};
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

#[derive(Default)]
struct RecordingBackend {
    preflight_calls: usize,
    close_calls: usize,
    arm_calls: usize,
    verify_calls: usize,
}

impl PlatformBackend for RecordingBackend {
    fn preflight(&mut self) -> PlatformFuture<'_, ()> {
        self.preflight_calls += 1;
        Box::pin(async { Ok(()) })
    }

    fn close_blocked_apps(&mut self) -> PlatformFuture<'_, ()> {
        self.close_calls += 1;
        Box::pin(async { Ok(()) })
    }

    fn arm_guard(&mut self, _guard: GuardKind) -> PlatformFuture<'_, ()> {
        self.arm_calls += 1;
        Box::pin(async { Ok(()) })
    }

    fn verify_guard(&mut self, _guard: GuardKind) -> PlatformFuture<'_, ()> {
        self.verify_calls += 1;
        Box::pin(async { Ok(()) })
    }
}

fn assert_complete_recovery(backend: &RecordingBackend) {
    assert_eq!(backend.preflight_calls, 1);
    assert_eq!(backend.close_calls, 1);
    assert_eq!(backend.arm_calls, 4);
    assert_eq!(backend.verify_calls, 4);
}

#[test]
fn restart_from_arming_recovers_to_locked_when_all_steps_are_healthy() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = RecordingBackend::default();
    let session_id = SessionId(84);
    store
        .set_active_session(session_id, SessionState::Arming)
        .unwrap();

    let state = block_on_ready(recover_session(&mut store, &mut backend)).unwrap();

    assert_eq!(state, SessionState::Locked);
    assert_complete_recovery(&backend);
    assert_eq!(
        store.active_session().unwrap().unwrap().state(),
        SessionState::Locked
    );
    assert_eq!(store.transition_count().unwrap(), 2);
}

#[test]
fn restart_from_locked_reenters_recovery_before_reporting_locked() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = RecordingBackend::default();
    let session_id = SessionId(86);
    store
        .set_active_session(session_id, SessionState::Locked)
        .unwrap();

    let state = block_on_ready(recover_session(&mut store, &mut backend)).unwrap();

    assert_eq!(state, SessionState::Locked);
    assert_complete_recovery(&backend);
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
