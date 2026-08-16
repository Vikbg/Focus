use focus_core::{
    ExecutableMatcher, ExecutionOrigin, ObservedExecutable, PackageIdentity, PackageKind,
};
use focus_linux::{
    ExecutionContextClassifier, ExecutionContextError, LinuxExecutionFacts,
    enrich_execution_context,
};

const EXECUTABLE_DIGEST: [u8; 32] = [0x11; 32];
const IDE_DIGEST: [u8; 32] = [0x22; 32];
const APPIMAGE_DIGEST: [u8; 32] = [0x33; 32];
const WINE_TARGET_DIGEST: [u8; 32] = [0x44; 32];

fn executable(path: &str, digest: [u8; 32]) -> ObservedExecutable {
    ObservedExecutable::new(path)
        .with_filesystem_identity(8, u64::from(digest[0]))
        .with_digest(digest)
}

fn classifier() -> ExecutionContextClassifier {
    ExecutionContextClassifier::new(vec![ExecutableMatcher::Digest(IDE_DIGEST)])
}

#[test]
fn verified_flatpak_marker_sets_package_and_origin_even_inside_user_systemd() {
    let base = executable("/usr/bin/bwrap", EXECUTABLE_DIGEST);
    let facts = LinuxExecutionFacts::new(vec!["/usr/bin/bwrap".to_owned()])
        .with_verified_flatpak_app_id("org.mozilla.firefox")
        .with_cgroup("/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak.scope");

    let observed = enrich_execution_context(base, &facts, &classifier()).unwrap();

    assert_eq!(observed.origin(), ExecutionOrigin::Flatpak);
    assert_eq!(
        observed.package(),
        Some(&PackageIdentity::new(
            PackageKind::Flatpak,
            "org.mozilla.firefox"
        ))
    );
}

#[test]
fn verified_snap_package_id_sets_stable_package_identity() {
    let base = executable("/snap/bin/spotify", EXECUTABLE_DIGEST);
    let facts = LinuxExecutionFacts::new(vec!["/snap/bin/spotify".to_owned()])
        .with_verified_snap_package_id("spotify");

    let observed = enrich_execution_context(base, &facts, &classifier()).unwrap();

    assert_eq!(observed.origin(), ExecutionOrigin::Snap);
    assert_eq!(
        observed.package(),
        Some(&PackageIdentity::new(PackageKind::Snap, "spotify"))
    );
}

#[test]
fn verified_appimage_digest_is_used_instead_of_mutable_image_path() {
    let base = executable("/tmp/.mount_focus/app", EXECUTABLE_DIGEST);
    let facts = LinuxExecutionFacts::new(vec![
        "/tmp/.mount_focus/app".to_owned(),
        "/home/student/renamed.AppImage".to_owned(),
    ])
    .with_verified_appimage_digest(APPIMAGE_DIGEST);

    let observed = enrich_execution_context(base, &facts, &classifier()).unwrap();

    assert_eq!(observed.origin(), ExecutionOrigin::AppImage);
    assert_eq!(observed.package().unwrap().kind(), PackageKind::AppImage);
    assert!(
        !observed
            .package()
            .unwrap()
            .id()
            .contains("renamed.AppImage")
    );
}

#[test]
fn verified_wine_target_digest_identifies_wrapped_windows_binary() {
    let base = executable("/usr/bin/wine64", EXECUTABLE_DIGEST);
    let facts = LinuxExecutionFacts::new(vec![
        "/usr/bin/wine64".to_owned(),
        "C:\\Games\\blocked.exe".to_owned(),
    ])
    .with_verified_wine_target_digest(WINE_TARGET_DIGEST);

    let observed = enrich_execution_context(base, &facts, &classifier()).unwrap();

    assert_eq!(observed.origin(), ExecutionOrigin::Wine);
    assert_eq!(observed.package().unwrap().kind(), PackageKind::Wine);
}

#[test]
fn package_like_strings_without_verified_markers_do_not_create_package_identity() {
    let base = executable("/usr/bin/launcher", EXECUTABLE_DIGEST);
    let facts = LinuxExecutionFacts::new(vec![
        "/usr/bin/launcher".to_owned(),
        "SNAP_NAME=spotify".to_owned(),
        "APPIMAGE=/home/student/fake.AppImage".to_owned(),
        "FLATPAK_ID=org.example.App".to_owned(),
    ]);

    let observed = enrich_execution_context(base, &facts, &classifier()).unwrap();

    assert_eq!(observed.origin(), ExecutionOrigin::Direct);
    assert!(observed.package().is_none());
}

#[test]
fn known_interpreter_with_script_argument_is_classified_as_interpreter() {
    let base = executable("/usr/bin/python3", EXECUTABLE_DIGEST);
    let facts = LinuxExecutionFacts::new(vec![
        "/usr/bin/python3".to_owned(),
        "/home/student/code/tool.py".to_owned(),
    ]);

    let observed = enrich_execution_context(base, &facts, &classifier()).unwrap();
    assert_eq!(observed.origin(), ExecutionOrigin::Interpreter);
}

#[test]
fn stable_ide_parent_identity_classifies_child_without_trusting_parent_name() {
    let parent = executable("/opt/editor/renamed-launcher", IDE_DIGEST);
    let base = executable("/home/student/code/target/debug/app", EXECUTABLE_DIGEST);
    let facts =
        LinuxExecutionFacts::new(vec![base.canonical_path().to_owned()]).with_parent(parent);

    let observed = enrich_execution_context(base, &facts, &classifier()).unwrap();

    assert_eq!(observed.origin(), ExecutionOrigin::IdeChild);
    assert_eq!(observed.parent().unwrap().digest(), Some(IDE_DIGEST));
}

#[test]
fn user_systemd_cgroup_classifies_background_app_scope() {
    let base = executable("/usr/bin/tool", EXECUTABLE_DIGEST);
    let facts = LinuxExecutionFacts::new(vec!["/usr/bin/tool".to_owned()])
        .with_cgroup("/user.slice/user-1000.slice/user@1000.service/app.slice/app-tool.scope");

    let observed = enrich_execution_context(base, &facts, &classifier()).unwrap();
    assert_eq!(observed.origin(), ExecutionOrigin::UserSystemd);
}

#[test]
fn cron_parent_classifies_cron_launch() {
    let parent = executable("/usr/sbin/cron", [0x55; 32]);
    let base = executable("/usr/bin/tool", EXECUTABLE_DIGEST);
    let facts = LinuxExecutionFacts::new(vec!["/usr/bin/tool".to_owned()]).with_parent(parent);

    let observed = enrich_execution_context(base, &facts, &classifier()).unwrap();
    assert_eq!(observed.origin(), ExecutionOrigin::Cron);
}

#[test]
fn container_cgroup_marker_classifies_container_launch() {
    let base = executable("/usr/bin/tool", EXECUTABLE_DIGEST);
    let facts = LinuxExecutionFacts::new(vec!["/usr/bin/tool".to_owned()])
        .with_cgroup("/system.slice/docker-0123456789abcdef.scope");

    let observed = enrich_execution_context(base, &facts, &classifier()).unwrap();
    assert_eq!(observed.origin(), ExecutionOrigin::Container);
}

#[test]
fn incompatible_verified_package_markers_are_rejected_instead_of_prioritized() {
    let base = executable("/usr/bin/launcher", EXECUTABLE_DIGEST);
    let facts = LinuxExecutionFacts::new(vec!["/usr/bin/launcher".to_owned()])
        .with_verified_flatpak_app_id("org.example.App")
        .with_verified_snap_package_id("different-app");

    assert!(matches!(
        enrich_execution_context(base, &facts, &classifier()),
        Err(ExecutionContextError::AmbiguousPackageMarkers)
    ));
}
