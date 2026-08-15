use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_platform::{FailClosedBackend, FakeBackend, GuardKind, PlatformBackend, PlatformError};

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test backend futures must resolve immediately"),
    }
}

#[test]
fn fake_backend_can_fail_each_guard_independently() {
    for guard in [
        GuardKind::Process,
        GuardKind::Network,
        GuardKind::Browser,
        GuardKind::Privilege,
    ] {
        let mut backend = FakeBackend::default();
        backend.fail_guard(guard);

        assert_eq!(
            block_on_ready(backend.arm_guard(guard)),
            Err(PlatformError::GuardFailed(guard))
        );

        for other in [
            GuardKind::Process,
            GuardKind::Network,
            GuardKind::Browser,
            GuardKind::Privilege,
        ] {
            if other != guard {
                assert_eq!(block_on_ready(backend.arm_guard(other)), Ok(()));
            }
        }
    }
}

#[test]
fn fail_closed_backend_never_claims_a_guard_is_armed() {
    let mut backend = FailClosedBackend;

    for guard in [
        GuardKind::Process,
        GuardKind::Network,
        GuardKind::Browser,
        GuardKind::Privilege,
    ] {
        assert_eq!(
            block_on_ready(backend.arm_guard(guard)),
            Err(PlatformError::GuardFailed(guard))
        );
    }
}
