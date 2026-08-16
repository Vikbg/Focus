use std::{
    cell::RefCell,
    collections::VecDeque,
    fs, io,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use focus_linux::{
    ExecutionContextClassifier, ExecutionFactCollectionError, LinuxExecutionFactSource,
    collect_execution_observation,
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Source {
    executable: PathBuf,
    stats: RefCell<VecDeque<String>>,
}

impl Source {
    fn new(executable: PathBuf, stats: impl IntoIterator<Item = String>) -> Self {
        Self {
            executable,
            stats: RefCell::new(stats.into_iter().collect()),
        }
    }
}

impl LinuxExecutionFactSource for Source {
    fn executable_path(&self, _pid: u32) -> io::Result<PathBuf> {
        Ok(self.executable.clone())
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
        self.stats
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "missing stat sample"))
    }

    fn flatpak_info(&self, _pid: u32) -> io::Result<Option<String>> {
        Ok(None)
    }

    fn security_label(&self, _pid: u32) -> io::Result<Option<String>> {
        Ok(None)
    }
}

fn stat(pid: u32, starttime: u64) -> String {
    let fields = (4_u8..=21)
        .map(|field| field.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    format!("{pid} (tool with spaces) S {fields} {starttime} 23 24\n")
}

fn executable() -> PathBuf {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "focus-pid-stability-{}-{sequence}",
        std::process::id()
    ));
    fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn unchanged_pid_starttime_allows_collection() {
    let executable = executable();
    let source = Source::new(executable.clone(), [stat(700, 12345), stat(700, 12345)]);
    let classifier = ExecutionContextClassifier::new(Vec::new());

    assert!(collect_execution_observation(&source, 700, &classifier).is_ok());

    let _ = fs::remove_file(executable);
}

#[test]
fn recycled_pid_is_rejected_even_when_numeric_pid_is_unchanged() {
    let executable = executable();
    let source = Source::new(executable.clone(), [stat(700, 12345), stat(700, 99999)]);
    let classifier = ExecutionContextClassifier::new(Vec::new());

    assert!(matches!(
        collect_execution_observation(&source, 700, &classifier),
        Err(ExecutionFactCollectionError::ProcessIdentityChanged)
    ));

    let _ = fs::remove_file(executable);
}

#[test]
fn malformed_proc_stat_fails_closed() {
    let executable = executable();
    let source = Source::new(
        executable.clone(),
        ["700 malformed\n".to_owned(), "700 malformed\n".to_owned()],
    );
    let classifier = ExecutionContextClassifier::new(Vec::new());

    assert!(matches!(
        collect_execution_observation(&source, 700, &classifier),
        Err(ExecutionFactCollectionError::InvalidProcessIdentity)
    ));

    let _ = fs::remove_file(executable);
}
