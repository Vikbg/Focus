use focus_core::{
    Decision, ExecutableMatcher, ExecutionOrigin, ObservedExecutable, PackageIdentity, PackageKind,
    ProcessEnforcementPlan, ProcessRule,
};

const BLOCKED_DIGEST: [u8; 32] = [0x42; 32];
const OTHER_DIGEST: [u8; 32] = [0x24; 32];
const POLICY_DIGEST: [u8; 32] = [0x91; 32];

fn native(path: &str, device: u64, inode: u64, digest: [u8; 32]) -> ObservedExecutable {
    ObservedExecutable::new(path)
        .with_filesystem_identity(device, inode)
        .with_digest(digest)
        .with_origin(ExecutionOrigin::Direct)
}

fn strict_plan() -> ProcessEnforcementPlan {
    ProcessEnforcementPlan::strict(
        POLICY_DIGEST,
        vec![
            ProcessRule::block(ExecutableMatcher::Digest(BLOCKED_DIGEST)),
            ProcessRule::block(ExecutableMatcher::Package(PackageIdentity::new(
                PackageKind::Flatpak,
                "com.example.Distractor",
            ))),
        ],
        vec!["/home/student/code".to_owned()],
    )
}

#[test]
fn renamed_or_hardlinked_blocked_binary_stays_blocked_by_digest() {
    let plan = strict_plan();
    let renamed = native("/tmp/renamed", 8, 100, BLOCKED_DIGEST);
    let hardlink = native("/home/student/code/tool", 8, 100, BLOCKED_DIGEST);

    assert!(matches!(plan.decide(&renamed), Decision::Block(_)));
    assert!(matches!(plan.decide(&hardlink), Decision::Block(_)));
}

#[test]
fn copied_blocked_binary_inside_trusted_workspace_stays_blocked() {
    let plan = strict_plan();
    let copied = native(
        "/home/student/code/build/not-suspicious",
        9,
        400,
        BLOCKED_DIGEST,
    );

    assert!(matches!(plan.decide(&copied), Decision::Block(_)));
}

#[test]
fn newly_built_binary_inside_trusted_workspace_can_run_when_classifiable() {
    let plan = strict_plan();
    let built = native(
        "/home/student/code/target/debug/my-program",
        9,
        401,
        OTHER_DIGEST,
    )
    .with_origin(ExecutionOrigin::IdeChild);

    assert_eq!(plan.decide(&built), Decision::Allow);
}

#[test]
fn package_identity_blocks_flatpak_independent_of_launcher_path() {
    let plan = strict_plan();
    let flatpak = native("/usr/bin/bwrap", 1, 44, OTHER_DIGEST)
        .with_package(PackageIdentity::new(
            PackageKind::Flatpak,
            "com.example.Distractor",
        ))
        .with_origin(ExecutionOrigin::Flatpak);

    assert!(matches!(plan.decide(&flatpak), Decision::Block(_)));
}

#[test]
fn strict_plan_fails_closed_when_executable_identity_is_unclassifiable() {
    let plan = strict_plan();
    let unknown = ObservedExecutable::new("/proc/self/fd/17")
        .with_origin(ExecutionOrigin::Container);

    assert!(matches!(plan.decide(&unknown), Decision::FailClosed(_)));
}

#[test]
fn execution_origin_is_preserved_for_wrappers_and_background_launchers() {
    for origin in [
        ExecutionOrigin::Interpreter,
        ExecutionOrigin::IdeChild,
        ExecutionOrigin::UserSystemd,
        ExecutionOrigin::Cron,
        ExecutionOrigin::Container,
        ExecutionOrigin::AppImage,
        ExecutionOrigin::Flatpak,
        ExecutionOrigin::Snap,
        ExecutionOrigin::Wine,
    ] {
        let executable = native("/usr/bin/launcher", 1, 9, OTHER_DIGEST).with_origin(origin);
        assert_eq!(executable.origin(), origin);
    }
}

#[test]
fn plan_exposes_the_exact_frozen_policy_digest() {
    let plan = strict_plan();
    assert_eq!(plan.policy_digest(), POLICY_DIGEST);
}
