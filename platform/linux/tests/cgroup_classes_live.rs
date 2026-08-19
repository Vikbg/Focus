use std::{
    env, fs,
    io,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use focus_linux::{
    ExecutionContextClassifier, FOCUS_CGROUP_ROOT, FocusCgroupClass, FocusCgroupControl,
    ProcfsExecutionFactSource, SystemCgroupControl, collect_running_process,
};

const SCENARIO: &str = "cgroup-classes-live";
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
const CLASS_NAMES: [&str; 5] = ["browser", "development", "vpn", "system", "blocked"];

fn unified_cgroup(pid: u32) -> String {
    let proc_path = format!("/proc/{pid}/cgroup");
    let text = fs::read_to_string(&proc_path).expect("process cgroup membership must be readable");
    let mut unified = text.lines().filter_map(|line| line.strip_prefix("0::"));
    let path = unified
        .next()
        .expect("process must have one unified cgroup v2 membership");
    assert!(
        unified.next().is_none(),
        "process must not have multiple unified cgroup v2 memberships"
    );
    assert!(path.starts_with('/'), "kernel cgroup path must be absolute");
    assert!(
        !path.split('/').any(|component| component == ".."),
        "kernel cgroup path must not contain parent traversal"
    );
    path.to_owned()
}

fn cgroup_fs_path(unified: &str) -> PathBuf {
    Path::new(CGROUP_MOUNT).join(unified.trim_start_matches('/'))
}

fn write_pid_to_cgroup(path: &Path, pid: u32) -> io::Result<()> {
    fs::write(path.join("cgroup.procs"), pid.to_string())
}

fn remove_focus_tree_best_effort() {
    for name in CLASS_NAMES {
        let _ = fs::remove_dir(Path::new(FOCUS_CGROUP_ROOT).join(name));
    }
    let _ = fs::remove_dir(FOCUS_CGROUP_ROOT);
}

struct LiveChild {
    child: Child,
    original_cgroup: String,
    restored: bool,
}

impl LiveChild {
    fn spawn() -> Self {
        let child = Command::new("/usr/bin/sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sleep fixture must start");
        let original_cgroup = unified_cgroup(child.id());
        Self {
            child,
            original_cgroup,
            restored: false,
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn restore(&mut self) {
        let original = cgroup_fs_path(&self.original_cgroup);
        write_pid_to_cgroup(&original, self.pid())
            .expect("fixture process must return to its original cgroup");
        self.restored = true;
    }
}

impl Drop for LiveChild {
    fn drop(&mut self) {
        if !self.restored {
            let original = cgroup_fs_path(&self.original_cgroup);
            let _ = write_pid_to_cgroup(&original, self.pid());
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        remove_focus_tree_best_effort();
    }
}

#[test]
#[ignore = "requires disposable root VM with writable cgroup v2"]
fn system_cgroup_control_moves_verifies_and_restores_real_process() {
    let scenario = env::var("FOCUS_VM_SCENARIO").expect("FOCUS_VM_SCENARIO must be set");
    assert_eq!(scenario, SCENARIO);
    assert!(
        Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "cgroup v2 controller file must exist"
    );
    assert!(
        !Path::new(FOCUS_CGROUP_ROOT).exists(),
        "disposable VM must start without pre-existing Focus cgroup state"
    );

    let mut child = LiveChild::spawn();
    let original_cgroup = child.original_cgroup.clone();
    let classifier = ExecutionContextClassifier::new(Vec::new());
    let process = collect_running_process(&ProcfsExecutionFactSource, child.pid(), &classifier)
        .expect("fixture process lifetime and executable must be observable");
    let lifetime = process.lifetime();
    let mut control = SystemCgroupControl;

    control
        .prepare_classes()
        .expect("Focus cgroup classes must be created");
    control
        .place_process(FocusCgroupClass::Browser, lifetime)
        .expect("fixture process must enter browser class");
    control
        .verify_process(FocusCgroupClass::Browser, lifetime)
        .expect("browser class membership must verify");

    assert_eq!(unified_cgroup(child.pid()), "/focus/browser");
    let browser_procs = fs::read_to_string(
        control
            .class_path(FocusCgroupClass::Browser)
            .join("cgroup.procs"),
    )
    .expect("browser cgroup.procs must be readable");
    assert!(
        browser_procs
            .lines()
            .any(|line| line == child.pid().to_string()),
        "browser cgroup.procs must contain the exact fixture pid"
    );

    child.restore();
    assert_eq!(unified_cgroup(child.pid()), original_cgroup);
    drop(child);
    assert!(
        !Path::new(FOCUS_CGROUP_ROOT).exists(),
        "Focus cgroup tree must be removable after restoring the fixture"
    );
}
