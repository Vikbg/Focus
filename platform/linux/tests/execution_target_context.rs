use std::{cell::Cell, io, path::PathBuf};

use focus_core::{ExecutionOrigin, ObservedExecutable, PackageIdentity, PackageKind};
use focus_linux::{
    ExecutionContextClassifier, LinuxExecutionFactSource, enrich_execution_target_context,
};

const TARGET_DIGEST: [u8; 32] = [0x83; 32];

#[derive(Debug)]
struct Source {
    stat_reads: Cell<u8>,
    change_lifetime: bool,
}

impl Source {
    const fn stable() -> Self {
        Self {
            stat_reads: Cell::new(0),
            change_lifetime: false,
        }
    }

    const fn changing() -> Self {
        Self {
            stat_reads: Cell::new(0),
            change_lifetime: true,
        }
    }
}

impl LinuxExecutionFactSource for Source {
    fn executable_path(&self, _pid: u32) -> io::Result<PathBuf> {
        Err(io::Error::other(
            "requester executable must not replace fanotify target identity",
        ))
    }

    fn cmdline_bytes(&self, _pid: u32) -> io::Result<Vec<u8>> {
        Ok(b"/usr/bin/flatpak\0run\0org.mozilla.firefox\0".to_vec())
    }

    fn cgroup_text(&self, _pid: u32) -> io::Result<String> {
        Ok("0::/user.slice/user-1000.slice/session-42.scope\n".to_owned())
    }

    fn status_text(&self, _pid: u32) -> io::Result<String> {
        Ok("Name:\tflatpak\nState:\tS (sleeping)\nPPid:\t0\n".to_owned())
    }

    fn stat_text(&self, pid: u32) -> io::Result<String> {
        let read = self.stat_reads.get();
        self.stat_reads.set(read.saturating_add(1));
        let starttime = if self.change_lifetime && read > 0 {
            99_999
        } else {
            42_424
        };
        let fields = (4_u8..=21)
            .map(|field| field.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        Ok(format!("{pid} (flatpak) S {fields} {starttime} 23 24\n"))
    }

    fn flatpak_info(&self, _pid: u32) -> io::Result<Option<String>> {
        Ok(Some(
            "[Application]\nname=org.mozilla.firefox\nruntime=org.freedesktop.Platform/x86_64/24.08\n"
                .to_owned(),
        ))
    }

    fn security_label(&self, _pid: u32) -> io::Result<Option<String>> {
        Ok(None)
    }
}

fn target() -> ObservedExecutable {
    ObservedExecutable::new("/opt/focus/fd-target")
        .with_filesystem_identity(8, 501)
        .with_digest(TARGET_DIGEST)
        .with_origin(ExecutionOrigin::Direct)
}

#[test]
fn requester_context_enriches_but_never_replaces_target_identity() {
    let observed = enrich_execution_target_context(
        &Source::stable(),
        4242,
        target(),
        &ExecutionContextClassifier::new(Vec::new()),
    )
    .unwrap();

    assert_eq!(observed.path(), "/opt/focus/fd-target");
    assert_eq!(observed.filesystem_identity(), Some((8, 501)));
    assert_eq!(observed.digest(), Some(TARGET_DIGEST));
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
fn requester_pid_lifetime_change_fails_closed() {
    assert!(
        enrich_execution_target_context(
            &Source::changing(),
            4242,
            target(),
            &ExecutionContextClassifier::new(Vec::new()),
        )
        .is_err()
    );
}
