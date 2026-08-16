use std::collections::{BTreeMap, BTreeSet};

use focus_core::{
    Decision, ExecutableMatcher, ExecutionOrigin, ObservedExecutable, ProcessEnforcementPlan,
    ProcessRule,
};
use focus_linux::{
    ProcessCloseError, ProcessControl, ProcessLifetime, RunningProcess, close_blocked_processes,
};

const POLICY_DIGEST: [u8; 32] = [0xA7; 32];
const BLOCKED_DIGEST: [u8; 32] = [0x41; 32];
const ALLOWED_DIGEST: [u8; 32] = [0x52; 32];
const UNKNOWN_DIGEST: [u8; 32] = [0x63; 32];

fn plan() -> ProcessEnforcementPlan {
    ProcessEnforcementPlan::strict(
        POLICY_DIGEST,
        vec![ProcessRule::block(ExecutableMatcher::Digest(BLOCKED_DIGEST))],
        vec!["/home/student/code".to_owned()],
    )
}

fn process(pid: u32, starttime: u64, path: &str, digest: [u8; 32]) -> RunningProcess {
    RunningProcess::new(
        ProcessLifetime::new(pid, starttime),
        ObservedExecutable::new(path)
            .with_filesystem_identity(8, u64::from(pid))
            .with_digest(digest)
            .with_origin(ExecutionOrigin::Direct),
    )
}

#[derive(Debug, Default)]
struct FakeControl {
    processes: BTreeMap<u32, Option<RunningProcess>>,
    changed_lifetimes: BTreeSet<u32>,
    open_failures: BTreeSet<u32>,
    terminate_failures: BTreeSet<u32>,
    opened: Vec<u32>,
    revalidated: Vec<u32>,
    terminated: Vec<u32>,
}

impl FakeControl {
    fn with_process(mut self, process: RunningProcess) -> Self {
        self.processes.insert(process.lifetime().pid(), Some(process));
        self
    }

    fn with_disappeared(mut self, pid: u32) -> Self {
        self.processes.insert(pid, None);
        self
    }
}

impl ProcessControl for FakeControl {
    type Handle = ProcessLifetime;

    fn process_ids(&self) -> Result<Vec<u32>, ProcessCloseError> {
        Ok(self.processes.keys().copied().collect())
    }

    fn observe_process(&self, pid: u32) -> Result<Option<RunningProcess>, ProcessCloseError> {
        self.processes
            .get(&pid)
            .cloned()
            .ok_or(ProcessCloseError::ObservationFailed(pid))
    }

    fn open_process_handle(
        &mut self,
        lifetime: ProcessLifetime,
    ) -> Result<Self::Handle, ProcessCloseError> {
        if self.open_failures.contains(&lifetime.pid()) {
            return Err(ProcessCloseError::HandleOpenFailed(lifetime.pid()));
        }
        self.opened.push(lifetime.pid());
        Ok(lifetime)
    }

    fn revalidate_process_handle(
        &mut self,
        handle: &Self::Handle,
        expected: ProcessLifetime,
    ) -> Result<(), ProcessCloseError> {
        self.revalidated.push(expected.pid());
        if handle != &expected || self.changed_lifetimes.contains(&expected.pid()) {
            return Err(ProcessCloseError::LifetimeChanged(expected.pid()));
        }
        Ok(())
    }

    fn terminate_process(&mut self, handle: &Self::Handle) -> Result<(), ProcessCloseError> {
        if self.terminate_failures.contains(&handle.pid()) {
            return Err(ProcessCloseError::TerminationFailed(handle.pid()));
        }
        self.terminated.push(handle.pid());
        Ok(())
    }
}

#[test]
fn explicit_block_is_terminated_but_allowed_workspace_process_is_untouched() {
    let mut control = FakeControl::default()
        .with_process(process(100, 1_000, "/tmp/renamed", BLOCKED_DIGEST))
        .with_process(process(
            101,
            1_001,
            "/home/student/code/target/debug/tool",
            ALLOWED_DIGEST,
        ));

    let report = close_blocked_processes(&mut control, &plan()).unwrap();

    assert_eq!(report.terminated_pids(), &[100]);
    assert_eq!(control.opened, vec![100]);
    assert_eq!(control.revalidated, vec![100]);
    assert_eq!(control.terminated, vec![100]);
}

#[test]
fn disappeared_process_is_ignored_without_weakening_other_decisions() {
    let mut control = FakeControl::default()
        .with_disappeared(99)
        .with_process(process(100, 1_000, "/tmp/renamed", BLOCKED_DIGEST));

    let report = close_blocked_processes(&mut control, &plan()).unwrap();

    assert_eq!(report.terminated_pids(), &[100]);
}

#[test]
fn policy_uncertainty_is_detected_before_any_termination_side_effect() {
    let mut control = FakeControl::default()
        .with_process(process(100, 1_000, "/tmp/renamed", BLOCKED_DIGEST))
        .with_process(process(101, 1_001, "/opt/unknown/tool", UNKNOWN_DIGEST));

    let error = close_blocked_processes(&mut control, &plan()).unwrap_err();

    assert_eq!(error, ProcessCloseError::PolicyUncertain(101));
    assert!(control.opened.is_empty());
    assert!(control.revalidated.is_empty());
    assert!(control.terminated.is_empty());
}

#[test]
fn lifetime_change_is_detected_before_any_termination_side_effect() {
    let mut control = FakeControl::default()
        .with_process(process(100, 1_000, "/tmp/one", BLOCKED_DIGEST))
        .with_process(process(101, 1_001, "/tmp/two", BLOCKED_DIGEST));
    control.changed_lifetimes.insert(101);

    let error = close_blocked_processes(&mut control, &plan()).unwrap_err();

    assert_eq!(error, ProcessCloseError::LifetimeChanged(101));
    assert_eq!(control.opened, vec![100, 101]);
    assert_eq!(control.revalidated, vec![100, 101]);
    assert!(control.terminated.is_empty());
}

#[test]
fn handle_open_failure_is_fail_closed_before_termination() {
    let mut control = FakeControl::default()
        .with_process(process(100, 1_000, "/tmp/one", BLOCKED_DIGEST))
        .with_process(process(101, 1_001, "/tmp/two", BLOCKED_DIGEST));
    control.open_failures.insert(101);

    let error = close_blocked_processes(&mut control, &plan()).unwrap_err();

    assert_eq!(error, ProcessCloseError::HandleOpenFailed(101));
    assert_eq!(control.opened, vec![100]);
    assert!(control.terminated.is_empty());
}

#[test]
fn termination_failure_is_reported_instead_of_claiming_success() {
    let mut control = FakeControl::default()
        .with_process(process(100, 1_000, "/tmp/one", BLOCKED_DIGEST));
    control.terminate_failures.insert(100);

    let error = close_blocked_processes(&mut control, &plan()).unwrap_err();

    assert_eq!(error, ProcessCloseError::TerminationFailed(100));
    assert_eq!(control.opened, vec![100]);
    assert_eq!(control.revalidated, vec![100]);
    assert!(control.terminated.is_empty());
}

#[test]
fn only_explicit_blocks_are_selected_for_termination() {
    let blocked = process(100, 1_000, "/tmp/blocked", BLOCKED_DIGEST);
    let unknown = process(101, 1_001, "/opt/unknown/tool", UNKNOWN_DIGEST);

    assert!(matches!(plan().decide(blocked.executable()), Decision::Block(_)));
    assert!(matches!(
        plan().decide(unknown.executable()),
        Decision::FailClosed(_)
    ));
}
