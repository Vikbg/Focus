use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use focus_core::{
    Decision, PolicySet, PolicyVersion, Profile, ProfileId, RecoveryCodeHash, SessionId,
    SessionState,
};
use focus_platform::{GuardKind, PlatformBackend, PlatformFuture, PlatformResult};
use focus_storage::{FocusStore, SqliteStore, StoredActiveSession};
use focusd::DaemonService;

const CODE: &str = "FG7K-P29M-4TXQ-R8VN";

struct PendingOnce {
    pending: bool,
}

impl Future for PendingOnce {
    type Output = PlatformResult<()>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.pending {
            self.pending = false;
            context.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

#[derive(Default)]
struct PendingOnceBackend {
    delayed_preflight: bool,
}

impl PlatformBackend for PendingOnceBackend {
    fn preflight(&mut self) -> PlatformFuture<'_, ()> {
        let pending = !self.delayed_preflight;
        self.delayed_preflight = true;
        Box::pin(PendingOnce { pending })
    }

    fn arm_guard(&mut self, _guard: GuardKind) -> PlatformFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

fn arming_session() -> StoredActiveSession {
    StoredActiveSession::new(
        SessionId(700),
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

#[tokio::test]
async fn daemon_service_recovery_completes_when_backend_future_is_initially_pending() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    store.set_active_session(&arming_session()).unwrap();
    let backend = PendingOnceBackend::default();
    let mut service = DaemonService::new(store, backend);

    let state = tokio::time::timeout(std::time::Duration::from_secs(1), service.recover())
        .await
        .expect("real runtime must keep polling a pending backend future")
        .unwrap();

    assert_eq!(state, SessionState::Locked);
    assert_eq!(service.state(), SessionState::Locked);
}
