use std::{
    fs::{self, File},
    os::{fd::AsFd, unix::fs::PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use focus_core::{ExecutionOrigin, PrivilegeTransition};
use focus_linux::{observe_executable, observe_open_executable};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn fixture_dir() -> PathBuf {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "focus-open-executable-identity-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn write_executable(path: &std::path::Path, body: &[u8]) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn opened_executable_identity_survives_path_replacement_without_toctou() {
    let dir = fixture_dir();
    let path = dir.join("target");
    write_executable(&path, b"#!/bin/sh\necho original\n");

    let expected = observe_executable(&path, ExecutionOrigin::Direct).unwrap();
    let opened = File::open(&path).unwrap();

    let moved = dir.join("original-moved");
    fs::rename(&path, &moved).unwrap();
    write_executable(&path, b"#!/bin/sh\necho replacement\n");
    let replacement = observe_executable(&path, ExecutionOrigin::Direct).unwrap();

    let observed = observe_open_executable(opened.as_fd(), ExecutionOrigin::Direct).unwrap();

    assert_eq!(
        observed.filesystem_identity(),
        expected.filesystem_identity()
    );
    assert_eq!(observed.digest(), expected.digest());
    assert_ne!(
        observed.filesystem_identity(),
        replacement.filesystem_identity()
    );
    assert_ne!(observed.digest(), replacement.digest());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn opened_setid_executable_is_marked_as_privilege_transition() {
    let dir = fixture_dir();
    let path = dir.join("setid-helper");
    write_executable(&path, b"#!/bin/sh\nexit 0\n");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o4755)).unwrap();
    let opened = File::open(&path).unwrap();

    let observed = observe_open_executable(opened.as_fd(), ExecutionOrigin::Direct).unwrap();

    assert_eq!(observed.privilege_transition(), PrivilegeTransition::SetId);

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn opened_non_executable_file_is_rejected() {
    let dir = fixture_dir();
    let path = dir.join("data");
    fs::write(&path, b"not executable").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let opened = File::open(&path).unwrap();

    assert!(observe_open_executable(opened.as_fd(), ExecutionOrigin::Direct).is_err());

    fs::remove_dir_all(dir).unwrap();
}
