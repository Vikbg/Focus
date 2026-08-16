use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_core::{
    Decision, PolicySet, PolicyVersion, Profile, ProfileId, RecoveryCodeHash, SessionId,
    SessionState,
};
use focus_platform::{GuardKind, PlatformBackend, PlatformError, PlatformFuture};
use focus_storage::{FocusStore, SqliteStore, StoredActiveSession};
use focusd::{ArmError, arm_session};

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("preflight fixture futures must resolve immediately"),
    }
}

fn session() -> StoredActiveSession {
    StoredActiveSession::new(
        SessionId(9_001),
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

#[derive(Debug, Default)]
struct DegradedPreflightBackend {
    arm_attempts: usize,
}

impl PlatformBackend for DegradedPreflightBackend {
    fn preflight(&mut self) -> PlatformFuture<'_, ()> {
        Box::pin(async { Err(PlatformError::PreflightFailed) })
    }

    fn arm_guard(&mut self, _guard: GuardKind) -> PlatformFuture<'_, ()> {
        self.arm_attempts += 1;
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn degraded_preflight_never_persists_or_reports_locked() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let mut backend = DegradedPreflightBackend::default();
    let session = session();

    let result = block_on_ready(arm_session(&mut store, &mut backend, &session));

    assert!(matches!(
        result,
        Err(ArmError::Platform(PlatformError::PreflightFailed))
    ));
    assert_eq!(backend.arm_attempts, 0);
    assert!(store.active_session().unwrap().is_none());
}
