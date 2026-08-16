use focus_core::{
    ExecutableMatcher, ExecutionOrigin, ObservedExecutable, ProcessEnforcementPlan, ProcessRule,
};
use focus_linux::{ExecutionPermission, decide_execution_permission};

const POLICY_DIGEST: [u8; 32] = [0xD1; 32];
const BLOCKED_DIGEST: [u8; 32] = [0x41; 32];
const ALLOWED_DIGEST: [u8; 32] = [0x52; 32];

fn plan() -> ProcessEnforcementPlan {
    ProcessEnforcementPlan::strict(
        POLICY_DIGEST,
        vec![ProcessRule::block(ExecutableMatcher::Digest(BLOCKED_DIGEST))],
        vec!["/home/student/code".to_owned()],
    )
}

fn observed(path: &str, digest: Option<[u8; 32]>) -> ObservedExecutable {
    let executable = ObservedExecutable::new(path).with_origin(ExecutionOrigin::Direct);
    match digest {
        Some(digest) => executable
            .with_filesystem_identity(8, 99)
            .with_digest(digest),
        None => executable,
    }
}

#[test]
fn explicitly_blocked_digest_is_denied_before_exec() {
    assert_eq!(
        decide_execution_permission(&plan(), &observed("/tmp/renamed", Some(BLOCKED_DIGEST))),
        ExecutionPermission::Deny
    );
}

#[test]
fn stable_executable_inside_trusted_workspace_is_allowed() {
    assert_eq!(
        decide_execution_permission(
            &plan(),
            &observed(
                "/home/student/code/target/debug/tool",
                Some(ALLOWED_DIGEST)
            )
        ),
        ExecutionPermission::Allow
    );
}

#[test]
fn stable_unknown_executable_outside_workspace_is_denied_fail_closed() {
    assert_eq!(
        decide_execution_permission(
            &plan(),
            &observed("/opt/unknown/tool", Some(ALLOWED_DIGEST))
        ),
        ExecutionPermission::Deny
    );
}

#[test]
fn executable_without_stable_identity_is_denied_fail_closed() {
    assert_eq!(
        decide_execution_permission(&plan(), &observed("/tmp/unclassifiable", None)),
        ExecutionPermission::Deny
    );
}
