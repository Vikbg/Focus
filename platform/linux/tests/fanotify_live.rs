use std::{
    fs, io,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
    sync::mpsc::{self, Receiver},
    thread,
    time::{Duration, Instant},
};

use focus_core::{ExecutableMatcher, ExecutionOrigin, ProcessEnforcementPlan, ProcessRule};
use focus_linux::{
    ExecutionContextClassifier, ExecutionPermissionStep, FanotifyExecutionChannel,
    NixFanotifyPermissionSource, ProcessGuardControl, ProcfsExecutionFactSource,
    ProductionProcessGuard, observe_executable, process_next_execution_permission,
};

const POLICY_DIGEST: [u8; 32] = [0xA4; 32];
const EVENT_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const IDLE_MEASUREMENT_WINDOW: Duration = Duration::from_millis(1_250);
const PROTECTED_UID: u32 = 60_000;

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

fn attempt_exec_as_uid(path: PathBuf, uid: u32) -> Receiver<io::Result<ExitStatus>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let result = Command::new(path).uid(uid).status();
        let _ = sender.send(result);
    });
    receiver
}

fn wait_for_next_watchdog_wakeup(guard: &ProductionProcessGuard, baseline: u64) {
    let deadline = Instant::now() + EVENT_TIMEOUT;
    loop {
        if guard.metrics().watchdog_wakeups() > baseline {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "process guard watchdog did not wake before timeout"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

fn assert_disposable_vm_fixture() {
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
}

fn blocked_plan(mount: &MountedTmpfs, blocked: &Path) -> ProcessEnforcementPlan {
    let blocked_digest = observe_executable(blocked, ExecutionOrigin::Direct)
        .unwrap()
        .digest()
        .unwrap();
    ProcessEnforcementPlan::strict(
        POLICY_DIGEST,
        vec![ProcessRule::block(ExecutableMatcher::Digest(
            blocked_digest,
        ))],
        vec![mount.path().to_string_lossy().into_owned()],
    )
}

#[test]
#[ignore = "requires disposable root VM with fanotify permission support"]
fn fanotify_open_exec_permission_blocks_and_allows_real_exec() {
    assert_disposable_vm_fixture();

    let mount = MountedTmpfs::mount().unwrap();
    let blocked = mount.path().join("blocked-true");
    let allowed = mount.path().join("allowed-echo");
    copy_executable("/bin/true", &blocked).unwrap();
    copy_executable("/bin/echo", &allowed).unwrap();

    let plan = blocked_plan(&mount, &blocked);
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

#[test]
#[ignore = "requires disposable root VM with fanotify permission support"]
fn production_process_guard_measures_real_decisions_and_idle_wakeups() {
    assert_disposable_vm_fixture();

    let mount = MountedTmpfs::mount().unwrap();
    let blocked = mount.path().join("blocked-true");
    let allowed = mount.path().join("allowed-echo");
    copy_executable("/bin/true", &blocked).unwrap();
    copy_executable("/bin/echo", &allowed).unwrap();
    let plan = blocked_plan(&mount, &blocked);

    let mut guard = ProductionProcessGuard::for_mounts_and_uid([mount.path()], PROTECTED_UID);
    guard.arm(&plan).unwrap();

    let idle_started = Instant::now();
    thread::sleep(IDLE_MEASUREMENT_WINDOW);
    let idle_elapsed = idle_started.elapsed();
    let idle_metrics = guard.metrics();
    assert!(
        idle_metrics.watchdog_wakeups() > 0,
        "watchdog did not run during the idle measurement window"
    );
    assert!(
        idle_metrics.watchdog_wakeups() <= 8,
        "idle watchdog woke too often: {} wakeups in {} ms",
        idle_metrics.watchdog_wakeups(),
        idle_elapsed.as_millis()
    );
    guard.verify(POLICY_DIGEST).unwrap();

    let watchdog_before_blocked = guard.metrics().watchdog_wakeups();
    wait_for_next_watchdog_wakeup(&guard, watchdog_before_blocked);
    let blocked_attempt = attempt_exec_as_uid(blocked, PROTECTED_UID);
    let blocked_result = blocked_attempt
        .recv_timeout(EVENT_TIMEOUT)
        .expect("blocked execution did not complete before timeout");
    let blocked_error = blocked_result.expect_err("blocked executable unexpectedly ran");
    assert_eq!(blocked_error.kind(), io::ErrorKind::PermissionDenied);
    guard.verify(POLICY_DIGEST).unwrap();

    let watchdog_before_allowed = guard.metrics().watchdog_wakeups();
    wait_for_next_watchdog_wakeup(&guard, watchdog_before_allowed);
    let allowed_attempt = attempt_exec_as_uid(allowed, PROTECTED_UID);
    let allowed_status = allowed_attempt
        .recv_timeout(EVENT_TIMEOUT)
        .expect("allowed execution did not complete before timeout")
        .unwrap();
    assert!(allowed_status.success());
    guard.verify(POLICY_DIGEST).unwrap();

    let metrics = guard.metrics();
    assert!(metrics.permission_decisions() >= 2);
    assert!(
        metrics.total_decision_latency() >= metrics.max_decision_latency(),
        "total decision latency cannot be smaller than the maximum decision latency"
    );
    assert!(metrics.average_decision_latency().is_some());

    println!(
        "process_guard_metrics decisions={} total_latency_ns={} max_latency_ns={} average_latency_ns={} watchdog_wakeups={} idle_window_ms={}",
        metrics.permission_decisions(),
        metrics.total_decision_latency().as_nanos(),
        metrics.max_decision_latency().as_nanos(),
        metrics
            .average_decision_latency()
            .map_or(0, |latency| latency.as_nanos()),
        metrics.watchdog_wakeups(),
        idle_elapsed.as_millis()
    );

    guard.disarm().unwrap();
}
