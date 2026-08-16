use focus_core::{
    Decision, ExecutableMatcher, ExecutionOrigin, ObservedExecutable, PolicySet, PolicyVersion,
    ProcessPolicy, ProcessRule, Profile, ProfileId, SessionPolicySnapshot,
};

const BLOCKED_DIGEST: [u8; 32] = [0x41; 32];
const OTHER_DIGEST: [u8; 32] = [0x52; 32];

fn profile(blocked_digest: [u8; 32], workspace: &str) -> Profile {
    Profile::new(
        ProfileId(7),
        PolicyVersion(11),
        PolicySet::new(Decision::Allow),
    )
    .with_process_policy(ProcessPolicy::strict(
        vec![ProcessRule::block(ExecutableMatcher::Digest(
            blocked_digest,
        ))],
        vec![workspace.to_owned()],
    ))
}

fn observed(path: &str, digest: [u8; 32]) -> ObservedExecutable {
    ObservedExecutable::new(path)
        .with_filesystem_identity(8, 99)
        .with_digest(digest)
        .with_origin(ExecutionOrigin::Direct)
}

#[test]
fn frozen_snapshot_reconstructs_process_plan_bound_to_its_own_digest() {
    let snapshot = profile(BLOCKED_DIGEST, "/home/student/code").snapshot();
    let plan = snapshot
        .process_enforcement_plan()
        .expect("new process-aware snapshot must contain a process policy");

    assert_eq!(plan.policy_digest(), snapshot.policy_sha256());
    assert!(matches!(
        plan.decide(&observed("/tmp/renamed", BLOCKED_DIGEST)),
        Decision::Block(_)
    ));
    assert_eq!(
        plan.decide(&observed(
            "/home/student/code/target/debug/tool",
            OTHER_DIGEST
        )),
        Decision::Allow
    );
}

#[test]
fn process_rules_and_workspace_roots_are_covered_by_snapshot_digest() {
    let original = profile(BLOCKED_DIGEST, "/home/student/code").snapshot();
    let changed_rule = profile(OTHER_DIGEST, "/home/student/code").snapshot();
    let changed_workspace = profile(BLOCKED_DIGEST, "/home/student/other").snapshot();

    assert_ne!(original.policy_sha256(), changed_rule.policy_sha256());
    assert_ne!(original.policy_sha256(), changed_workspace.policy_sha256());
}

#[test]
fn process_policy_round_trip_restores_exact_enforcement_semantics() {
    let original = profile(BLOCKED_DIGEST, "/home/student/code").snapshot();
    let payload = original.policy_payload();
    let restored = SessionPolicySnapshot::restore(
        original.profile_id(),
        original.profile_version(),
        original.schema_version(),
        &payload,
    )
    .expect("current process-aware snapshot must restore");

    assert_eq!(restored.policy_sha256(), original.policy_sha256());

    let original_plan = original.process_enforcement_plan().unwrap();
    let restored_plan = restored.process_enforcement_plan().unwrap();
    for executable in [
        observed("/tmp/copied", BLOCKED_DIGEST),
        observed("/home/student/code/bin/tool", OTHER_DIGEST),
        observed("/opt/unknown/tool", OTHER_DIGEST),
    ] {
        assert_eq!(
            restored_plan.decide(&executable),
            original_plan.decide(&executable)
        );
    }
}
