use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_linux::{
    FailClosedProcessGuard, LinuxBackend, LinuxError, PrivilegeGuardControl, PrivilegeGuardError,
    ProcessCloseError, ProcessControl, ProcessLifetime, RunningProcess, SystemProbe,
};
use focus_platform::{GuardKind, PlatformBackend, PlatformError};

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("Linux backend fixture futures must resolve immediately"),
    }
}

#[derive(Debug, Clone, Copy)]
struct HealthyProbe;

impl SystemProbe for HealthyProbe {
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
struct EmptyProcessControl;

impl ProcessControl for EmptyProcessControl {
    type Handle = ProcessLifetime;

    fn process_ids(&self) -> Result<Vec<u32>, ProcessCloseError> {
        Ok(Vec::new())
    }

    fn observe_process(&self, _pid: u32) -> Result<Option<RunningProcess>, ProcessCloseError> {
        Ok(None)
    }

    fn open_process_handle(
        &mut self,
        lifetime: ProcessLifetime,
    ) -> Result<Self::Handle, ProcessCloseError> {
        Ok(lifetime)
    }

    fn revalidate_process_handle(
        &mut self,
        _handle: &Self::Handle,
        _expected: ProcessLifetime,
    ) -> Result<(), ProcessCloseError> {
        Ok(())
    }

    fn terminate_process(&mut self, _handle: &Self::Handle) -> Result<(), ProcessCloseError> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct RecordingPrivilegeGuard {
    arm_calls: usize,
    verify_calls: usize,
    disarm_calls: usize,
    fail_arm: bool,
    fail_verify: bool,
    fail_disarm: bool,
}

impl PrivilegeGuardControl for RecordingPrivilegeGuard {
    fn arm(&mut self) -> Result<(), PrivilegeGuardError> {
        self.arm_calls += 1;
        if self.fail_arm {
            Err(PrivilegeGuardError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn verify(&mut self) -> Result<(), PrivilegeGuardError> {
        self.verify_calls += 1;
        if self.fail_verify {
            Err(PrivilegeGuardError::Unhealthy)
        } else {
            Ok(())
        }
    }

    fn disarm(&mut self) -> Result<(), PrivilegeGuardError> {
        self.disarm_calls += 1;
        if self.fail_disarm {
            Err(PrivilegeGuardError::DisarmFailed)
        } else {
            Ok(())
        }
    }
}

fn backend(
    privilege_guard: RecordingPrivilegeGuard,
) -> LinuxBackend<HealthyProbe, EmptyProcessControl, FailClosedProcessGuard, RecordingPrivilegeGuard>
{
    LinuxBackend::with_controls(
        HealthyProbe,
        EmptyProcessControl,
        FailClosedProcessGuard,
        privilege_guard,
    )
}

#[test]
fn privilege_arm_routes_to_the_typed_guard_controller() {
    let mut backend = backend(RecordingPrivilegeGuard::default());

    assert_eq!(
        block_on_ready(backend.arm_guard(GuardKind::Privilege)),
        Ok(())
    );
    assert_eq!(backend.privilege_guard().arm_calls, 1);
}

#[test]
fn privilege_verify_routes_to_the_typed_guard_controller() {
    let mut backend = backend(RecordingPrivilegeGuard::default());

    assert_eq!(
        block_on_ready(backend.verify_guard(GuardKind::Privilege)),
        Ok(())
    );
    assert_eq!(backend.privilege_guard().verify_calls, 1);
}

#[test]
fn privilege_disarm_routes_to_the_typed_guard_controller() {
    let mut backend = backend(RecordingPrivilegeGuard::default());

    assert_eq!(
        block_on_ready(backend.disarm_guard(GuardKind::Privilege)),
        Ok(())
    );
    assert_eq!(backend.privilege_guard().disarm_calls, 1);
}

#[test]
fn privilege_guard_failures_map_to_platform_guard_failure() {
    let mut arm_failure = backend(RecordingPrivilegeGuard {
        fail_arm: true,
        ..RecordingPrivilegeGuard::default()
    });
    assert_eq!(
        block_on_ready(arm_failure.arm_guard(GuardKind::Privilege)),
        Err(PlatformError::GuardFailed(GuardKind::Privilege))
    );

    let mut verify_failure = backend(RecordingPrivilegeGuard {
        fail_verify: true,
        ..RecordingPrivilegeGuard::default()
    });
    assert_eq!(
        block_on_ready(verify_failure.verify_guard(GuardKind::Privilege)),
        Err(PlatformError::GuardFailed(GuardKind::Privilege))
    );

    let mut disarm_failure = backend(RecordingPrivilegeGuard {
        fail_disarm: true,
        ..RecordingPrivilegeGuard::default()
    });
    assert_eq!(
        block_on_ready(disarm_failure.disarm_guard(GuardKind::Privilege)),
        Err(PlatformError::GuardFailed(GuardKind::Privilege))
    );
}
