use std::{
    cell::RefCell,
    collections::VecDeque,
    fs, io,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use focus_core::{ExecutableMatcher, ProcessEnforcementPlan, ProcessRule};
use focus_linux::{
    ExecutionContextClassifier, LinuxExecutionFactSource, LinuxProcessControl,
    LinuxProcessInventorySource, ProcessCloseError, ProcessHandleOps, close_blocked_processes,
};

const POLICY_DIGEST: [u8; 32] = [0xB4; 32];
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn stat(pid: u32, starttime: u64) -> String {
    let fields = (4_u8..=21)
        .map(|field| field.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    format!("{pid} (tool) S {fields} {starttime} 23 24\n")
}

fn executable() -> PathBuf {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "focus-linux-process-control-{}-{sequence}",
        std::process::id()
    ));
    fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

struct Source {
    pid: u32,
    executable: PathBuf,
    stats: RefCell<VecDeque<io::Result<String>>>,
}

impl Source {
    fn new(
        pid: u32,
        executable: PathBuf,
        stats: impl IntoIterator<Item = io::Result<String>>,
    ) -> Self {
        Self {
            pid,
            executable,
            stats: RefCell::new(stats.into_iter().collect()),
        }
    }
}

impl LinuxExecutionFactSource for Source {
    fn executable_path(&self, pid: u32) -> io::Result<PathBuf> {
        if pid == self.pid {
            Ok(self.executable.clone())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process disappeared",
            ))
        }
    }

    fn cmdline_bytes(&self, _pid: u32) -> io::Result<Vec<u8>> {
        Ok(b"/tmp/tool\0".to_vec())
    }

    fn cgroup_text(&self, _pid: u32) -> io::Result<String> {
        Ok("0::/user.slice/user-1000.slice/session.scope\n".to_owned())
    }

    fn status_text(&self, _pid: u32) -> io::Result<String> {
        Ok("Name:\ttool\nPPid:\t0\n".to_owned())
    }

    fn stat_text(&self, _pid: u32) -> io::Result<String> {
        self.stats.borrow_mut().pop_front().unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process disappeared",
            ))
        })
    }

    fn flatpak_info(&self, _pid: u32) -> io::Result<Option<String>> {
        Ok(None)
    }

    fn security_label(&self, _pid: u32) -> io::Result<Option<String>> {
        Ok(None)
    }
}

impl LinuxProcessInventorySource for Source {
    fn process_ids(&self) -> io::Result<Vec<u32>> {
        Ok(vec![self.pid])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Handle(u32);

#[derive(Debug, Default)]
struct Ops {
    opened: Vec<u32>,
    terminated: Vec<u32>,
}

impl ProcessHandleOps for Ops {
    type Handle = Handle;

    fn open_process(&mut self, pid: u32) -> io::Result<Self::Handle> {
        self.opened.push(pid);
        Ok(Handle(pid))
    }

    fn terminate_process(&mut self, handle: &Self::Handle) -> io::Result<()> {
        self.terminated.push(handle.0);
        Ok(())
    }
}

fn plan(digest: [u8; 32]) -> ProcessEnforcementPlan {
    ProcessEnforcementPlan::strict(
        POLICY_DIGEST,
        vec![ProcessRule::block(ExecutableMatcher::Digest(digest))],
        Vec::new(),
    )
}

#[test]
fn linux_control_revalidates_proc_starttime_after_handle_open_before_termination() {
    let path = executable();
    let observed_digest =
        focus_linux::observe_executable(&path, focus_core::ExecutionOrigin::Direct)
            .unwrap()
            .digest()
            .unwrap();
    let source = Source::new(
        700,
        path.clone(),
        [
            Ok(stat(700, 12_345)),
            Ok(stat(700, 12_345)),
            Ok(stat(700, 12_345)),
        ],
    );
    let mut control = LinuxProcessControl::new(
        source,
        Ops::default(),
        ExecutionContextClassifier::new(Vec::new()),
    );

    let report = close_blocked_processes(&mut control, &plan(observed_digest)).unwrap();

    assert_eq!(report.terminated_pids(), &[700]);
    assert_eq!(control.handle_ops().opened, vec![700]);
    assert_eq!(control.handle_ops().terminated, vec![700]);
    let _ = fs::remove_file(path);
}

#[test]
fn pid_reuse_after_handle_open_fails_closed_before_signal() {
    let path = executable();
    let observed_digest =
        focus_linux::observe_executable(&path, focus_core::ExecutionOrigin::Direct)
            .unwrap()
            .digest()
            .unwrap();
    let source = Source::new(
        701,
        path.clone(),
        [
            Ok(stat(701, 20_000)),
            Ok(stat(701, 20_000)),
            Ok(stat(701, 20_001)),
        ],
    );
    let mut control = LinuxProcessControl::new(
        source,
        Ops::default(),
        ExecutionContextClassifier::new(Vec::new()),
    );

    let error = close_blocked_processes(&mut control, &plan(observed_digest)).unwrap_err();

    assert_eq!(error, ProcessCloseError::LifetimeChanged(701));
    assert_eq!(control.handle_ops().opened, vec![701]);
    assert!(control.handle_ops().terminated.is_empty());
    let _ = fs::remove_file(path);
}

#[test]
fn disappearing_proc_entry_is_treated_as_gone_not_as_an_unknown_process() {
    let path = executable();
    let source = Source::new(
        702,
        path.clone(),
        [Err(io::Error::new(io::ErrorKind::NotFound, "gone"))],
    );
    let mut control = LinuxProcessControl::new(
        source,
        Ops::default(),
        ExecutionContextClassifier::new(Vec::new()),
    );

    let report = close_blocked_processes(&mut control, &plan([0x11; 32])).unwrap();

    assert!(report.terminated_pids().is_empty());
    assert!(control.handle_ops().opened.is_empty());
    assert!(control.handle_ops().terminated.is_empty());
    let _ = fs::remove_file(path);
}
