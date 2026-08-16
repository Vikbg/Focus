use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_core::{
    ExecutableMatcher, ExecutionOrigin, ObservedExecutable, ProcessEnforcementPlan, ProcessRule,
};
use focus_linux::{
    Health, LinuxBackend, LinuxError, ProcessCloseError, ProcessControl, ProcessLifetime,
    RunningProcess, SystemProbe,
};
use focus_platform::{PlatformBackend, PlatformError};

const POLICY_DIGEST: [u8; 32] = [0xC1; 32];
const BLOCKED_DIGEST: [u8; 32] = [0x41; 32];
const UNKNOWN_DIGEST: [u8; 32] = [0x52; 32];

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

#[derive(Debug)]
struct Control {
    process: RunningProcess,
    terminated: bool,
}

impl Control {
    fn new(pid: u32, path: &str, digest: [u8; 32]) -> Self {
        Self {
            process: RunningProcess::new(
                ProcessLifetime::new(pid, 10_000),
                ObservedExecutable::new(path)
                    .with_filesystem_identity(8, u64::from(pid))
                    .with_digest(digest)
                    .with_origin(ExecutionOrigin::Direct),
            ),
            terminated: false,
        }
    }
}

impl ProcessControl for Control {
    type Handle = ProcessLifetime;

    fn process_ids(&self) -> Result<Vec<u32>, ProcessCloseError> {
        Ok(vec![self.process.lifetime().pid()])
    }

    fn observe_process(&self, _pid: u32) -> Result<Option<RunningProcess>, ProcessCloseError> {
        Ok(Some(self.process.clone()))
    }

    fn open_process_handle(
        &mut self,
        lifetime: ProcessLifetime,
    ) -> Result<Self::Handle, ProcessCloseError> {
        Ok(lifetime)
    }

    fn revalidate_process_handle(
        &mut self,
        handle: &Self::Handle,
        expected: ProcessLifetime,
    ) -> Result<(), ProcessCloseError> {
        if *handle == expected {
            Ok(())
        } else {
            Err(ProcessCloseError::LifetimeChanged(expected.pid()))
        }
    }

    fn terminate_process(&mut self, _handle: &Self::Handle) -> Result<(), ProcessCloseError> {
        self.terminated = true;
        Ok(())
    }
}

fn plan() -> ProcessEnforcementPlan {
    ProcessEnforcementPlan::strict(
        POLICY_DIGEST,
        vec![ProcessRule::block(ExecutableMatcher::Digest(
            BLOCKED_DIGEST,
        ))],
        Vec::new(),
    )
}

#[test]
fn linux_backend_closes_explicitly_blocked_processes_with_the_frozen_plan() {
    let control = Control::new(700, "/tmp/renamed", BLOCKED_DIGEST);
    let mut backend = LinuxBackend::with_probe_and_process_control(HealthyProbe, control);

    let result = block_on_ready(backend.close_blocked_apps(&plan()));

    assert_eq!(result, Ok(()));
    assert!(backend.process_control().terminated);
}

#[test]
fn linux_backend_maps_policy_uncertainty_to_close_blocked_apps_failure() {
    let control = Control::new(701, "/opt/unknown/tool", UNKNOWN_DIGEST);
    let mut backend = LinuxBackend::with_probe_and_process_control(HealthyProbe, control);

    let result = block_on_ready(backend.close_blocked_apps(&plan()));

    assert_eq!(result, Err(PlatformError::CloseBlockedAppsFailed));
    assert!(!backend.process_control().terminated);
}

#[test]
fn typed_process_guard_remains_fail_closed_after_initial_close_support() {
    let control = Control::new(702, "/tmp/renamed", BLOCKED_DIGEST);
    let mut backend = LinuxBackend::with_probe_and_process_control(HealthyProbe, control);
    let process_plan = plan();

    assert_eq!(
        block_on_ready(backend.arm_process_guard(&process_plan)),
        Err(PlatformError::GuardFailed(
            focus_platform::GuardKind::Process
        ))
    );
}

#[test]
fn healthy_probe_type_remains_healthy() {
    let probe = HealthyProbe;
    assert_eq!(probe.active_user_count().unwrap(), 1);
    let _ = Health::Healthy;
}
