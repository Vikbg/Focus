use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use focus_core::ExecutionOrigin;
use focus_linux::observe_executable;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn fixture_dir() -> PathBuf {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "focus-executable-identity-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn executable_fixture(dir: &std::path::Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, b"#!/bin/sh\necho focus-identity\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn rename_preserves_filesystem_identity_and_digest() {
    let dir = fixture_dir();
    let original = executable_fixture(&dir, "original");
    let before = observe_executable(&original, ExecutionOrigin::Direct).unwrap();
    let renamed = dir.join("renamed");
    fs::rename(&original, &renamed).unwrap();
    let after = observe_executable(&renamed, ExecutionOrigin::Direct).unwrap();

    assert_eq!(before.filesystem_identity(), after.filesystem_identity());
    assert_eq!(before.digest(), after.digest());
    assert_ne!(before.canonical_path(), after.canonical_path());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn hardlink_and_symlink_resolve_to_the_same_underlying_identity() {
    let dir = fixture_dir();
    let original = executable_fixture(&dir, "original");
    let hardlink = dir.join("hardlink");
    let symlink = dir.join("symlink");
    fs::hard_link(&original, &hardlink).unwrap();
    std::os::unix::fs::symlink(&original, &symlink).unwrap();

    let original_identity = observe_executable(&original, ExecutionOrigin::Direct).unwrap();
    let hardlink_identity = observe_executable(&hardlink, ExecutionOrigin::Direct).unwrap();
    let symlink_identity = observe_executable(&symlink, ExecutionOrigin::Direct).unwrap();

    assert_eq!(
        original_identity.filesystem_identity(),
        hardlink_identity.filesystem_identity()
    );
    assert_eq!(
        original_identity.filesystem_identity(),
        symlink_identity.filesystem_identity()
    );
    assert_eq!(original_identity.digest(), hardlink_identity.digest());
    assert_eq!(original_identity.digest(), symlink_identity.digest());
    assert_eq!(
        original_identity.canonical_path(),
        symlink_identity.canonical_path()
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn copied_binary_changes_filesystem_identity_but_keeps_digest() {
    let dir = fixture_dir();
    let original = executable_fixture(&dir, "original");
    let copied = dir.join("copied");
    fs::copy(&original, &copied).unwrap();
    fs::set_permissions(&copied, fs::Permissions::from_mode(0o755)).unwrap();

    let original_identity = observe_executable(&original, ExecutionOrigin::Direct).unwrap();
    let copied_identity = observe_executable(&copied, ExecutionOrigin::Direct).unwrap();

    assert_ne!(
        original_identity.filesystem_identity(),
        copied_identity.filesystem_identity()
    );
    assert_eq!(original_identity.digest(), copied_identity.digest());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn non_regular_or_non_executable_paths_are_rejected() {
    let dir = fixture_dir();
    let not_executable = dir.join("data");
    fs::write(&not_executable, b"not executable").unwrap();
    fs::set_permissions(&not_executable, fs::Permissions::from_mode(0o644)).unwrap();

    assert!(observe_executable(&dir, ExecutionOrigin::Direct).is_err());
    assert!(observe_executable(&not_executable, ExecutionOrigin::Direct).is_err());

    fs::remove_dir_all(dir).unwrap();
}
