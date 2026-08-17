use std::{
    fs::{self, File},
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use focus_core::{ExecutableMatcher, ExecutionOrigin, ProcessEnforcementPlan, ProcessRule};
use focus_linux::{
    ExecutionContextClassifier, ExecutionPermission, ExecutionPermissionStep,
    FanotifyExecutionChannel, FanotifyExecutionEvent, FanotifyPermissionSource,
    LinuxExecutionFactSource, process_next_execution_permission,
};

const POLICY_DIGEST: [u8; 32] = [0xC2; 32];
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn fixture_dir() -> PathBuf {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "focus-fanotify-uid-scope-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn executable(path: &Path) {
    fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn stat(pid: u32) -> String {
    let fields = (4_u8..=21)
        .map(|field| field.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    format!("{pid} (requester) S {fields} 42424 23 24\n")
}

#[derive(Debug)]
struct Facts {
    uid: io::Result<u32>,
    context_reads: Arc<AtomicUsize>,
}

impl Facts {
    fn readable(uid: u32, context_reads: Arc<AtomicUsize>) -> Self {
        Self {
            uid: Ok(uid),
            context_reads,
        }
    }

    fn unreadable(context_reads: Arc<AtomicUsize>) -> Self {
        Self {
            uid: Err(io::Error::other("uid unavailable")),
            context_reads,
        }
    }
}

impl LinuxExecutionFactSource for Facts {
    fn executable_path(&self, _pid: u32) -> io::Result<PathBuf> {
        Err(io::Error::other("requester executable is not the target"))
    }

    fn cmdline_bytes(&self, _pid: u32) -> io::Result<Vec<u8>> {
        self.context_reads.fetch_add(1, Ordering::Relaxed);
        Ok(b"/usr/bin/launcher\0".to_vec())
    }

    fn cgroup_text(&self, _pid: u32) -> io::Result<String> {
        self.context_reads.fetch_add(1, Ordering::Relaxed);
        Ok("0::/user.slice/user-1000.slice/session.scope\n".to_owned())
    }

    fn status_text(&self, _pid: u32) -> io::Result<String> {
        match &self.uid {
            Ok(uid) => Ok(format!(
                "Name:\tlauncher\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nPPid:\t0\n"
            )),
            Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
        }
    }

    fn stat_text(&self, pid: u32) -> io::Result<String> {
        self.context_reads.fetch_add(1, Ordering::Relaxed);
        Ok(stat(pid))
    }

    fn flatpak_info(&self, _pid: u32) -> io::Result<Option<String>> {
        self.context_reads.fetch_add(1, Ordering::Relaxed);
        Ok(None)
    }

    fn security_label(&self, _pid: u32) -> io::Result<Option<String>> {
        self.context_reads.fetch_add(1, Ordering::Relaxed);
        Ok(None)
    }
}

#[derive(Debug, Default)]
struct SourceState {
    responses: Vec<ExecutionPermission>,
}

#[derive(Debug)]
struct Source {
    event: Option<FanotifyExecutionEvent>,
    state: Arc<Mutex<SourceState>>,
}

impl Source {
    fn with_event(event: FanotifyExecutionEvent) -> (Self, Arc<Mutex<SourceState>>) {
        let state = Arc::new(Mutex::new(SourceState::default()));
        (
            Self {
                event: Some(event),
                state: Arc::clone(&state),
            },
            state,
        )
    }
}

impl FanotifyPermissionSource for Source {
    fn next_event(&mut self) -> io::Result<Option<FanotifyExecutionEvent>> {
        Ok(self.event.take())
    }

    fn respond(&mut self, permission: ExecutionPermission) -> io::Result<()> {
        self.state.lock().unwrap().responses.push(permission);
        Ok(())
    }
}

fn blocked_plan(target: &Path, workspace: &Path) -> ProcessEnforcementPlan {
    let observed = focus_linux::observe_executable(target, ExecutionOrigin::Direct).unwrap();
    ProcessEnforcementPlan::strict(
        POLICY_DIGEST,
        vec![ProcessRule::block(ExecutableMatcher::Digest(
            observed.digest().unwrap(),
        ))],
        vec![workspace.to_string_lossy().into_owned()],
    )
}

#[test]
fn out_of_scope_uid_is_allowed_without_running_focus_policy() {
    let dir = fixture_dir();
    let target = dir.join("blocked");
    executable(&target);
    let plan = blocked_plan(&target, &dir);
    let reads = Arc::new(AtomicUsize::new(0));
    let (source, state) = Source::with_event(FanotifyExecutionEvent::new(
        File::open(&target).unwrap(),
        4242,
    ));
    let mut channel = FanotifyExecutionChannel::for_uid(
        source,
        Facts::readable(0, Arc::clone(&reads)),
        ExecutionContextClassifier::new(Vec::new()),
        1000,
    );

    let step = process_next_execution_permission(&mut channel, &plan).unwrap();

    assert_eq!(step, ExecutionPermissionStep::Idle);
    assert_eq!(
        state.lock().unwrap().responses,
        vec![ExecutionPermission::Allow]
    );
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn protected_uid_still_receives_the_frozen_policy_decision() {
    let dir = fixture_dir();
    let target = dir.join("blocked");
    executable(&target);
    let plan = blocked_plan(&target, &dir);
    let reads = Arc::new(AtomicUsize::new(0));
    let (source, state) = Source::with_event(FanotifyExecutionEvent::new(
        File::open(&target).unwrap(),
        4242,
    ));
    let mut channel = FanotifyExecutionChannel::for_uid(
        source,
        Facts::readable(1000, Arc::clone(&reads)),
        ExecutionContextClassifier::new(Vec::new()),
        1000,
    );

    let step = process_next_execution_permission(&mut channel, &plan).unwrap();

    assert_eq!(step, ExecutionPermissionStep::Denied);
    assert_eq!(
        state.lock().unwrap().responses,
        vec![ExecutionPermission::Deny]
    );
    assert!(reads.load(Ordering::Relaxed) > 0);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unreadable_requester_uid_is_denied_fail_closed() {
    let dir = fixture_dir();
    let target = dir.join("target");
    executable(&target);
    let plan = ProcessEnforcementPlan::strict(
        POLICY_DIGEST,
        Vec::new(),
        vec![dir.to_string_lossy().into_owned()],
    );
    let reads = Arc::new(AtomicUsize::new(0));
    let (source, state) = Source::with_event(FanotifyExecutionEvent::new(
        File::open(&target).unwrap(),
        4242,
    ));
    let mut channel = FanotifyExecutionChannel::for_uid(
        source,
        Facts::unreadable(reads),
        ExecutionContextClassifier::new(Vec::new()),
        1000,
    );

    let step = process_next_execution_permission(&mut channel, &plan).unwrap();

    assert_eq!(step, ExecutionPermissionStep::Denied);
    assert_eq!(
        state.lock().unwrap().responses,
        vec![ExecutionPermission::Deny]
    );
    fs::remove_dir_all(dir).unwrap();
}
