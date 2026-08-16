use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    thread,
    time::{Duration, Instant},
};

use focus_core::{ExecutableMatcher, ExecutionOrigin, ProcessEnforcementPlan, ProcessRule};
use focus_linux::{
    ExecutionContextClassifier, ExecutionPermissionStep, FanotifyExecutionChannel,
    NixFanotifyPermissionSource, ProcfsExecutionFactSource, observe_executable,
    process_next_execution_permission,
};

const POLICY_DIGEST: [u8; 32] = [0xA4; 32];
const EVENT_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(5);

struct MountedTmpfs {
    path: PathBuf,
}

impl MountedTmpfs {
    fn mount() -> io::Result<Self> {
        let path = PathBuf::from(format!("/mnt/focus-fanotify-live-{}", std::process::id()));
        fs::create_dir_all(&path)?;
        let status = Command::new("mount")
            .args(["-t", "tmpfs", "-o", "mode=0755,nosuid,nodev"])
            .arg("focus-fanotify-live")
            .arg(&path)
            .status()?;
        if !status.success() {
            return Err(io::Error::other("failed to mount isolated fanotify tmpfs"));
        }
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for MountedTmpfs {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.path).status();
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn copy_executable(source: &str, destination: &Path) -> io::Result<()> {
    fs::copy(source, destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o755))
}

fn wait_for_permission_step(
    channel: &mut FanotifyExecutionChannel<NixFanotifyPermissionSource, ProcfsExecutionFactSource>,
    plan: &ProcessEnforcementPlan,
) -> io::Result<ExecutionPermissionStep> {
    let deadline = Instant::now() + EVENT_TIMEOUT;
    loop {
        let step = process_next_execution_permission(channel, plan)?;
        if step != ExecutionPermissionStep::Idle {
            return Ok(step);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fanotify permission event did not arrive before timeout",
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn attempt_exec(path: PathBuf) -> thread::JoinHandle<io::Result<ExitStatus>> {
    thread::spawn(move || Command::new(path).status())
}

#[test]
#[ignore = "requires disposable root VM with fanotify permission support"]
fn fanotify_open_exec_permission_blocks_and_allows_real_exec() {
    assert_eq!(
        std::env::var("FOCUS_VM_SCENARIO").as_deref(),
        Ok("fanotify-permission"),
        "live fanotify fixture must run only through the disposable VM harness"
    );
    assert!(
        Command::new("systemd-detect-virt")
            .arg("--vm")
            .status()
            .unwrap()
            .success(),
        "live fanotify fixture requires a virtual machine"
    );

    let mount = MountedTmpfs::mount().unwrap();
    let blocked = mount.path().join("blocked-true");
    let allowed = mount.path().join("allowed-echo");
    copy_executable("/bin/true", &blocked).unwrap();
    copy_executable("/bin/echo", &allowed).unwrap();

    let blocked_digest = observe_executable(&blocked, ExecutionOrigin::Direct)
        .unwrap()
        .digest()
        .unwrap();
    let plan = ProcessEnforcementPlan::strict(
        POLICY_DIGEST,
        vec![ProcessRule::block(ExecutableMatcher::Digest(
            blocked_digest,
        ))],
        vec![mount.path().to_string_lossy().into_owned()],
    );

    let source = NixFanotifyPermissionSource::new_for_mounts([mount.path()]).unwrap();
    let mut channel = FanotifyExecutionChannel::new(
        source,
        ProcfsExecutionFactSource,
        ExecutionContextClassifier::new(Vec::new()),
    );

    let blocked_attempt = attempt_exec(blocked);
    let blocked_step = wait_for_permission_step(&mut channel, &plan).unwrap();
    assert_eq!(blocked_step, ExecutionPermissionStep::Denied);
    let blocked_error = blocked_attempt
        .join()
        .unwrap()
        .expect_err("blocked executable unexpectedly ran");
    assert_eq!(blocked_error.kind(), io::ErrorKind::PermissionDenied);

    let allowed_attempt = attempt_exec(allowed);
    let allowed_step = wait_for_permission_step(&mut channel, &plan).unwrap();
    assert_eq!(allowed_step, ExecutionPermissionStep::Allowed);
    assert!(allowed_attempt.join().unwrap().unwrap().success());

    drop(channel);
}
