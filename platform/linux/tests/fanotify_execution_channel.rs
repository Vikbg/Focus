use std::{
    cell::Cell,
    collections::VecDeque,
    fs::{self, File},
    io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, atomic::{AtomicU64, Ordering}},
};

use focus_core::{
    ExecutableMatcher, ExecutionOrigin, ProcessEnforcementPlan, ProcessRule,
};
use focus_linux::{
    ExecutionContextClassifier, ExecutionPermission, ExecutionPermissionChannel,
    ExecutionPermissionStep, FanotifyChannelHealth, FanotifyExecutionChannel,
    FanotifyExecutionEvent, FanotifyPermissionSource, LinuxExecutionFactSource,
    process_next_execution_permission,
};

const POLICY_DIGEST: [u8; 32] = [0x91; 32];
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn fixture_dir() -> PathBuf {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "focus-fanotify-channel-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn executable(path: &Path, body: &[u8]) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn stat(pid: u32) -> String {
    let fields = (4_u8..=21)
        .map(|field| field.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    format!("{pid} (requester) S {fields} 42424 23 24\n")
}

#[derive(Debug, Default)]
struct Facts;

impl LinuxExecutionFactSource for Facts {
    fn executable_path(&self, _pid: u32) -> io::Result<PathBuf> {
        Err(io::Error::other("requester executable is not the target"))
    }

    fn cmdline_bytes(&self, _pid: u32) -> io::Result<Vec<u8>> {
        Ok(b"/usr/bin/launcher\0".to_vec())
    }

    fn cgroup_text(&self, _pid: u32) -> io::Result<String> {
        Ok("0::/user.slice/user-1000.slice/session-1.scope\n".to_owned())
    }

    fn status_text(&self, _pid: u32) -> io::Result<String> {
        Ok("Name:\tlauncher\nState:\tS (sleeping)\nPPid:\t0\n".to_owned())
    }

    fn stat_text(&self, pid: u32) -> io::Result<String> {
        Ok(stat(pid))
    }

    fn flatpak_info(&self, _pid: u32) -> io::Result<Option<String>> {
        Ok(None)
    }

    fn security_label(&self, _pid: u32) -> io::Result<Option<String>> {
        Ok(None)
    }
}

#[derive(Debug, Default)]
struct BrokenFacts {
    reads: Cell<u8>,
}

impl LinuxExecutionFactSource for BrokenFacts {
    fn executable_path(&self, _pid: u32) -> io::Result<PathBuf> {
        Err(io::Error::other("unused"))
    }

    fn cmdline_bytes(&self, _pid: u32) -> io::Result<Vec<u8>> {
        self.reads.set(self.reads.get().saturating_add(1));
        Err(io::Error::other("requester context unavailable"))
    }

    fn cgroup_text(&self, _pid: u32) -> io::Result<String> {
        Err(io::Error::other("unused"))
    }

    fn status_text(&self, _pid: u32) -> io::Result<String> {
        Err(io::Error::other("unused"))
    }

    fn stat_text(&self, pid: u32) -> io::Result<String> {
        Ok(stat(pid))
    }

    fn flatpak_info(&self, _pid: u32) -> io::Result<Option<String>> {
        Ok(None)
    }

    fn security_label(&self, _pid: u32) -> io::Result<Option<String>> {
        Ok(None)
    }
}

#[derive(Debug, Default)]
struct SourceState {
    responses: Vec<ExecutionPermission>,
}

#[derive(Debug)]
struct Source {
    events: VecDeque<FanotifyExecutionEvent>,
    state: Arc<Mutex<SourceState>>,
    fail_read: bool,
    fail_response: bool,
}

impl Source {
    fn with_event(event: FanotifyExecutionEvent) -> (Self, Arc<Mutex<SourceState>>) {
        let state = Arc::new(Mutex::new(SourceState::default()));
        (
            Self {
                events: VecDeque::from([event]),
                state: Arc::clone(&state),
                fail_read: false,
                fail_response: false,
            },
            state,
        )
    }
}

impl FanotifyPermissionSource for Source {
    fn next_event(&mut self) -> io::Result<Option<FanotifyExecutionEvent>> {
        if self.fail_read {
            return Err(io::Error::other("simulated fanotify read failure"));
        }
        Ok(self.events.pop_front())
    }

    fn respond(&mut self, permission: ExecutionPermission) -> io::Result<()> {
        if self.fail_response {
            return Err(io::Error::other("simulated fanotify response failure"));
        }
        self.state.lock().unwrap().responses.push(permission);
        Ok(())
    }
}

#[test]
fn fd_target_is_classified_and_denied_through_permission_response() {
    let dir = fixture_dir();
    let target = dir.join("blocked");
    executable(&target, b"blocked executable");
    let observed = focus_linux::observe_executable(&target, ExecutionOrigin::Direct).unwrap();
    let digest = observed.digest().unwrap();
    let file = File::open(&target).unwrap();
    let plan = ProcessEnforcementPlan::strict(
        POLICY_DIGEST,
        vec![ProcessRule::block(ExecutableMatcher::Digest(digest))],
        vec![dir.to_string_lossy().into_owned()],
    );
    let (source, state) = Source::with_event(FanotifyExecutionEvent::new(file, 4242));
    let mut channel = FanotifyExecutionChannel::new(
        source,
        Facts,
        ExecutionContextClassifier::new(Vec::new()),
    );

    let step = process_next_execution_permission(&mut channel, &plan).unwrap();

    assert_eq!(step, ExecutionPermissionStep::Denied);
    assert_eq!(
        state.lock().unwrap().responses,
        vec![ExecutionPermission::Deny]
    );
    assert_eq!(channel.health(), FanotifyChannelHealth::Healthy);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn requester_context_failure_becomes_unclassifiable_and_is_denied() {
    let dir = fixture_dir();
    let target = dir.join("target");
    executable(&target, b"target executable");
    let file = File::open(&target).unwrap();
    let plan = ProcessEnforcementPlan::strict(POLICY_DIGEST, Vec::new(), vec![dir.to_string_lossy().into_owned()]);
    let (source, state) = Source::with_event(FanotifyExecutionEvent::new(file, 4242));
    let mut channel = FanotifyExecutionChannel::new(
        source,
        BrokenFacts::default(),
        ExecutionContextClassifier::new(Vec::new()),
    );

    let step = process_next_execution_permission(&mut channel, &plan).unwrap();

    assert_eq!(step, ExecutionPermissionStep::Denied);
    assert_eq!(
        state.lock().unwrap().responses,
        vec![ExecutionPermission::Deny]
    );
    assert_eq!(channel.health(), FanotifyChannelHealth::Healthy);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn fanotify_read_failure_marks_channel_unhealthy() {
    let state = Arc::new(Mutex::new(SourceState::default()));
    let source = Source {
        events: VecDeque::new(),
        state,
        fail_read: true,
        fail_response: false,
    };
    let mut channel = FanotifyExecutionChannel::new(
        source,
        Facts,
        ExecutionContextClassifier::new(Vec::new()),
    );

    assert!(ExecutionPermissionChannel::next_attempt(&mut channel).is_err());
    assert_eq!(channel.health(), FanotifyChannelHealth::Failed);
}

#[test]
fn fanotify_response_failure_marks_channel_unhealthy() {
    let dir = fixture_dir();
    let target = dir.join("target");
    executable(&target, b"target executable");
    let file = File::open(&target).unwrap();
    let (mut source, _) = Source::with_event(FanotifyExecutionEvent::new(file, 4242));
    source.fail_response = true;
    let mut channel = FanotifyExecutionChannel::new(
        source,
        Facts,
        ExecutionContextClassifier::new(Vec::new()),
    );

    assert!(ExecutionPermissionChannel::next_attempt(&mut channel).unwrap().is_some());
    assert!(ExecutionPermissionChannel::respond(&mut channel, ExecutionPermission::Deny).is_err());
    assert_eq!(channel.health(), FanotifyChannelHealth::Failed);
    fs::remove_dir_all(dir).unwrap();
}
