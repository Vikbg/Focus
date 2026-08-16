use std::{collections::VecDeque, io};

use focus_core::{
    ExecutableMatcher, ExecutionOrigin, ObservedExecutable, ProcessEnforcementPlan, ProcessRule,
};
use focus_linux::{
    ExecutionAttempt, ExecutionPermission, ExecutionPermissionChannel, ExecutionPermissionStep,
    process_next_execution_permission,
};

const POLICY_DIGEST: [u8; 32] = [0xD2; 32];
const BLOCKED_DIGEST: [u8; 32] = [0x61; 32];
const ALLOWED_DIGEST: [u8; 32] = [0x72; 32];

fn plan() -> ProcessEnforcementPlan {
    ProcessEnforcementPlan::strict(
        POLICY_DIGEST,
        vec![ProcessRule::block(ExecutableMatcher::Digest(
            BLOCKED_DIGEST,
        ))],
        vec!["/home/student/code".to_owned()],
    )
}

fn observed(path: &str, digest: [u8; 32]) -> ObservedExecutable {
    ObservedExecutable::new(path)
        .with_filesystem_identity(8, 101)
        .with_digest(digest)
        .with_origin(ExecutionOrigin::Direct)
}

#[derive(Debug, Default)]
struct FakeChannel {
    attempts: VecDeque<ExecutionAttempt>,
    responses: Vec<ExecutionPermission>,
    fail_response: bool,
}

impl FakeChannel {
    fn with_attempt(attempt: ExecutionAttempt) -> Self {
        Self {
            attempts: VecDeque::from([attempt]),
            ..Self::default()
        }
    }
}

impl ExecutionPermissionChannel for FakeChannel {
    fn next_attempt(&mut self) -> io::Result<Option<ExecutionAttempt>> {
        Ok(self.attempts.pop_front())
    }

    fn respond(&mut self, permission: ExecutionPermission) -> io::Result<()> {
        if self.fail_response {
            return Err(io::Error::other("simulated fanotify response failure"));
        }
        self.responses.push(permission);
        Ok(())
    }
}

#[test]
fn explicitly_blocked_execution_is_denied_before_exec() {
    let mut channel = FakeChannel::with_attempt(ExecutionAttempt::Observed(observed(
        "/tmp/renamed",
        BLOCKED_DIGEST,
    )));

    let step = process_next_execution_permission(&mut channel, &plan()).unwrap();

    assert_eq!(step, ExecutionPermissionStep::Denied);
    assert_eq!(channel.responses, vec![ExecutionPermission::Deny]);
}

#[test]
fn only_explicit_allow_is_allowed_before_exec() {
    let mut channel = FakeChannel::with_attempt(ExecutionAttempt::Observed(observed(
        "/home/student/code/target/debug/tool",
        ALLOWED_DIGEST,
    )));

    let step = process_next_execution_permission(&mut channel, &plan()).unwrap();

    assert_eq!(step, ExecutionPermissionStep::Allowed);
    assert_eq!(channel.responses, vec![ExecutionPermission::Allow]);
}

#[test]
fn unclassifiable_execution_is_denied_fail_closed() {
    let mut channel = FakeChannel::with_attempt(ExecutionAttempt::Unclassifiable);

    let step = process_next_execution_permission(&mut channel, &plan()).unwrap();

    assert_eq!(step, ExecutionPermissionStep::Denied);
    assert_eq!(channel.responses, vec![ExecutionPermission::Deny]);
}

#[test]
fn idle_channel_produces_no_permission_response() {
    let mut channel = FakeChannel::default();

    let step = process_next_execution_permission(&mut channel, &plan()).unwrap();

    assert_eq!(step, ExecutionPermissionStep::Idle);
    assert!(channel.responses.is_empty());
}

#[test]
fn response_failure_is_reported_instead_of_claiming_enforcement() {
    let mut channel = FakeChannel::with_attempt(ExecutionAttempt::Observed(observed(
        "/tmp/renamed",
        BLOCKED_DIGEST,
    )));
    channel.fail_response = true;

    let error = process_next_execution_permission(&mut channel, &plan()).unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(channel.responses.is_empty());
}
