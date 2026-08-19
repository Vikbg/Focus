use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_linux::{LinuxBackend, LinuxError, NetworkGuardControl, NetworkGuardError, SystemProbe};
use focus_platform::{GuardKind, PlatformBackend, PlatformError};

#[derive(Debug, Clone, Copy)]
struct Probe;

impl SystemProbe for Probe {
    fn systemd_available(&self) -> Result<bool, LinuxError> {
        Ok(true)
    }

    fn cgroup_v2_available(&self) -> Result<bool, LinuxError> {
        Ok(true)
    }

    fn fanotify_available(&self) -> Result<bool, LinuxError> {
        Ok(true)
    }

    fn nftables_available(&self) -> Result<bool, LinuxError> {
        Ok(true)
    }

    fn filesystem_permissions_ready(&self) -> Result<bool, LinuxError> {
        Ok(true)
    }

    fn privilege_model_ready(&self) -> Result<bool, LinuxError> {
        Ok(true)
    }

    fn active_user_count(&self) -> Result<usize, LinuxError> {
        Ok(1)
    }
}

#[derive(Debug, Default)]
struct RecordingNetworkGuard {
    arm_calls: usize,
    verify_calls: usize,
    disarm_calls: usize,
    fail_arm: bool,
}

impl NetworkGuardControl for RecordingNetworkGuard {
    fn arm(&mut self) -> Result<(), NetworkGuardError> {
        self.arm_calls += 1;
        if self.fail_arm {
            return Err(NetworkGuardError::Nftables(
                focus_linux::FocusNftablesError::ApplyFailed,
            ));
        }
        Ok(())
    }

    fn verify(&mut self) -> Result<(), NetworkGuardError> {
        self.verify_calls += 1;
        Ok(())
    }

    fn disarm(&mut self) -> Result<(), NetworkGuardError> {
        self.disarm_calls += 1;
        Ok(())
    }
}

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("Linux backend network guard operation must resolve synchronously"),
    }
}

#[test]
fn network_guard_routes_through_typed_controller() {
    let mut backend =
        LinuxBackend::with_probe_and_network_guard(Probe, RecordingNetworkGuard::default());

    assert_eq!(
        block_on_ready(backend.arm_guard(GuardKind::Network)),
        Ok(())
    );
    assert_eq!(
        block_on_ready(backend.verify_guard(GuardKind::Network)),
        Ok(())
    );
    assert_eq!(
        block_on_ready(backend.disarm_guard(GuardKind::Network)),
        Ok(())
    );

    let guard = backend.network_guard();
    assert_eq!(guard.arm_calls, 1);
    assert_eq!(guard.verify_calls, 1);
    assert_eq!(guard.disarm_calls, 1);
}

#[test]
fn network_guard_failure_maps_to_network_platform_error() {
    let mut backend = LinuxBackend::with_probe_and_network_guard(
        Probe,
        RecordingNetworkGuard {
            fail_arm: true,
            ..RecordingNetworkGuard::default()
        },
    );

    assert_eq!(
        block_on_ready(backend.arm_guard(GuardKind::Network)),
        Err(PlatformError::GuardFailed(GuardKind::Network))
    );
}
