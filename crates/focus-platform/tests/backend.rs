use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_core::ProcessEnforcementPlan;
use focus_platform::{FailClosedBackend, FakeBackend, GuardKind, PlatformBackend, PlatformError};

const POLICY_DIGEST: [u8; 32] = [0xA5; 32];

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test backend futures must resolve immediately"),
    }
}

fn process_plan() -> ProcessEnforcementPlan {
    ProcessEnforcementPlan::strict(POLICY_DIGEST, Vec::new(), Vec::new())
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
        let plan = process_plan();
        backend.fail_guard(guard);

        let failed = if guard == GuardKind::Process {
            block_on_ready(backend.arm_process_guard(&plan))
        } else {
            block_on_ready(backend.arm_guard(guard))
        };
        assert_eq!(failed, Err(PlatformError::GuardFailed(guard)));

        for other in [
            GuardKind::Process,
            GuardKind::Network,
            GuardKind::Browser,
            GuardKind::Privilege,
        ] {
            if other == guard {
                continue;
            }
            let result = if other == GuardKind::Process {
                block_on_ready(backend.arm_process_guard(&plan))
            } else {
                block_on_ready(backend.arm_guard(other))
            };
            assert_eq!(result, Ok(()));
        }
    }
}

#[test]
fn fail_closed_backend_never_claims_a_guard_is_armed() {
    let mut backend = FailClosedBackend;
    let plan = process_plan();

    assert_eq!(
        block_on_ready(backend.arm_process_guard(&plan)),
        Err(PlatformError::GuardFailed(GuardKind::Process))
    );

    for guard in [GuardKind::Network, GuardKind::Browser, GuardKind::Privilege] {
        assert_eq!(
            block_on_ready(backend.arm_guard(guard)),
            Err(PlatformError::GuardFailed(guard))
        );
    }
}
