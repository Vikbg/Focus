use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_linux::{LinuxBackend, LinuxError, SystemProbe};
use focus_platform::{GuardKind, PlatformBackend, PlatformError};

#[derive(Debug, Clone, Copy)]
struct Probe {
    missing: Option<&'static str>,
    active_users: usize,
}

impl Probe {
    const fn healthy() -> Self {
        Self {
            missing: None,
            active_users: 1,
        }
    }

    fn available(&self, capability: &'static str) -> bool {
        self.missing != Some(capability)
    }
}

impl SystemProbe for Probe {
    fn systemd_available(&self) -> Result<bool, LinuxError> {
        Ok(self.available("systemd"))
    }

    fn cgroup_v2_available(&self) -> Result<bool, LinuxError> {
        Ok(self.available("cgroup_v2"))
    }

    fn fanotify_available(&self) -> Result<bool, LinuxError> {
        Ok(self.available("fanotify"))
    }

    fn nftables_available(&self) -> Result<bool, LinuxError> {
        Ok(self.available("nftables"))
    }

    fn filesystem_permissions_ready(&self) -> Result<bool, LinuxError> {
        Ok(self.available("filesystem_permissions"))
    }

    fn privilege_model_ready(&self) -> Result<bool, LinuxError> {
        Ok(self.available("privilege_model"))
    }

    fn active_user_count(&self) -> Result<usize, LinuxError> {
        Ok(self.active_users)
    }
}

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("Linux backend preflight must resolve without host mutation"),
    }
}

#[test]
fn degraded_linux_backend_preflight_fails_closed() {
    let mut backend = LinuxBackend::with_probe(Probe {
        missing: Some("fanotify"),
        ..Probe::healthy()
    });

    assert_eq!(
        block_on_ready(backend.preflight()),
        Err(PlatformError::PreflightFailed)
    );
}

#[test]
fn healthy_preflight_does_not_claim_unimplemented_guards_are_armed() {
    let mut backend = LinuxBackend::with_probe(Probe::healthy());

    assert_eq!(block_on_ready(backend.preflight()), Ok(()));
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
