use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_core::ProcessEnforcementPlan;
use focus_linux::{
    LinuxBackend, LinuxError, ProcessCloseError, ProcessControl, ProcessGuardControl,
    ProcessGuardError, ProcessLifetime, RunningProcess, SystemProbe,
};
use focus_platform::{GuardKind, PlatformBackend, PlatformError};

const POLICY_DIGEST: [u8; 32] = [0xB4; 32];
const OTHER_DIGEST: [u8; 32] = [0xC5; 32];

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
struct RecordingGuard {
    armed_digest: Option<[u8; 32]>,
    arm_calls: usize,
    verify_calls: usize,
    disarm_calls: usize,
    healthy: bool,
}

impl RecordingGuard {
    fn healthy() -> Self {
        Self {
            healthy: true,
            ..Self::default()
        }
    }
}

impl ProcessGuardControl for RecordingGuard {
    fn arm(&mut self, plan: &ProcessEnforcementPlan) -> Result<(), ProcessGuardError> {
        self.arm_calls += 1;
        self.armed_digest = Some(plan.policy_digest());
        Ok(())
    }

    fn verify(&mut self, expected_policy_digest: [u8; 32]) -> Result<(), ProcessGuardError> {
        self.verify_calls += 1;
        if self.healthy && self.armed_digest == Some(expected_policy_digest) {
            Ok(())
        } else {
            Err(ProcessGuardError::Unhealthy)
        }
    }

    fn disarm(&mut self) -> Result<(), ProcessGuardError> {
        self.disarm_calls += 1;
        self.armed_digest = None;
        Ok(())
    }
}

fn plan(digest: [u8; 32]) -> ProcessEnforcementPlan {
    ProcessEnforcementPlan::strict(digest, Vec::new(), vec!["/home/student/code".to_owned()])
}

#[test]
fn typed_process_arm_and_verify_use_the_exact_frozen_policy_digest() {
    let mut backend = LinuxBackend::with_probe_process_control_and_guard(
        HealthyProbe,
        EmptyProcessControl,
        RecordingGuard::healthy(),
    );
    let process_plan = plan(POLICY_DIGEST);

    assert_eq!(
        block_on_ready(backend.arm_process_guard(&process_plan)),
        Ok(())
    );
    assert_eq!(
        block_on_ready(backend.verify_process_guard(POLICY_DIGEST)),
        Ok(())
    );
    assert_eq!(backend.process_guard().armed_digest, Some(POLICY_DIGEST));
    assert_eq!(backend.process_guard().arm_calls, 1);
    assert_eq!(backend.process_guard().verify_calls, 1);
}

#[test]
fn process_verification_rejects_a_different_policy_digest() {
    let mut backend = LinuxBackend::with_probe_process_control_and_guard(
        HealthyProbe,
        EmptyProcessControl,
        RecordingGuard::healthy(),
    );
    let process_plan = plan(POLICY_DIGEST);
    assert_eq!(
        block_on_ready(backend.arm_process_guard(&process_plan)),
        Ok(())
    );

    assert_eq!(
        block_on_ready(backend.verify_process_guard(OTHER_DIGEST)),
        Err(PlatformError::GuardFailed(GuardKind::Process))
    );
}

#[test]
fn process_disarm_routes_to_the_typed_guard_controller() {
    let mut backend = LinuxBackend::with_probe_process_control_and_guard(
        HealthyProbe,
        EmptyProcessControl,
        RecordingGuard::healthy(),
    );
    let process_plan = plan(POLICY_DIGEST);
    assert_eq!(
        block_on_ready(backend.arm_process_guard(&process_plan)),
        Ok(())
    );

    assert_eq!(
        block_on_ready(backend.disarm_guard(GuardKind::Process)),
        Ok(())
    );
    assert_eq!(backend.process_guard().armed_digest, None);
    assert_eq!(backend.process_guard().disarm_calls, 1);
}

#[test]
fn unhealthy_typed_guard_never_reports_process_verification_success() {
    let mut backend = LinuxBackend::with_probe_process_control_and_guard(
        HealthyProbe,
        EmptyProcessControl,
        RecordingGuard::healthy(),
    );
    let process_plan = plan(POLICY_DIGEST);
    assert_eq!(
        block_on_ready(backend.arm_process_guard(&process_plan)),
        Ok(())
    );
    backend.process_guard_mut().healthy = false;

    assert_eq!(
        block_on_ready(backend.verify_process_guard(POLICY_DIGEST)),
        Err(PlatformError::GuardFailed(GuardKind::Process))
    );
}
