use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use focus_core::{
    BlockReason, Decision, ExecutableMatcher, ExecutionOrigin, ProcessEnforcementPlan, ProcessRule,
};
use focus_linux::observe_executable;

const POLICY_DIGEST: [u8; 32] = [0xD2; 32];

struct TestWorkspace {
    root: PathBuf,
}

impl TestWorkspace {
    fn new() -> io::Result<Self> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "focus-development-workspace-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn approved(&self) -> PathBuf {
        self.root.join("approved")
    }

    fn outside(&self) -> PathBuf {
        self.root.join("outside")
    }
}

impl Drop for TestWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn available_c_compiler() -> &'static str {
    for compiler in ["gcc", "clang"] {
        if Command::new(compiler)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return compiler;
        }
    }
    panic!("Task 20 integration test requires GCC or Clang");
}

fn compile_fixture(compiler: &str, directory: &Path, name: &str, exit_code: u8) -> PathBuf {
    fs::create_dir_all(directory).unwrap();
    let source = directory.join(format!("{name}.c"));
    let executable = directory.join(name);
    fs::write(
        &source,
        format!("int main(void) {{ return {exit_code}; }}\n"),
    )
    .unwrap();

    let status = Command::new(compiler)
        .arg(&source)
        .arg("-O0")
        .arg("-o")
        .arg(&executable)
        .status()
        .unwrap();
    assert!(status.success(), "C fixture compilation failed");
    executable
}

#[test]
fn compiled_workspace_binary_runs_but_copied_blocked_binary_stays_blocked() {
    let compiler = available_c_compiler();
    let workspace = TestWorkspace::new().unwrap();
    let approved = workspace.approved();
    let outside = workspace.outside();

    let allowed = compile_fixture(compiler, &approved, "allowed-fixture", 0);
    let blocked_original = compile_fixture(compiler, &outside, "blocked-fixture", 0);
    let blocked_digest = observe_executable(&blocked_original, ExecutionOrigin::Direct)
        .unwrap()
        .digest()
        .unwrap();

    let blocked_copy = approved.join("blocked-copy");
    fs::copy(&blocked_original, &blocked_copy).unwrap();
    fs::set_permissions(&blocked_copy, fs::Permissions::from_mode(0o755)).unwrap();

    let trusted_root = fs::canonicalize(&approved)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let plan = ProcessEnforcementPlan::strict(
        POLICY_DIGEST,
        vec![ProcessRule::block(ExecutableMatcher::Digest(
            blocked_digest,
        ))],
        vec![trusted_root],
    );

    let allowed_observation = observe_executable(&allowed, ExecutionOrigin::Direct).unwrap();
    assert_eq!(plan.decide(&allowed_observation), Decision::Allow);
    assert!(Command::new(&allowed).status().unwrap().success());

    let copied_observation = observe_executable(&blocked_copy, ExecutionOrigin::Direct).unwrap();
    assert_eq!(copied_observation.digest(), Some(blocked_digest));
    assert_eq!(
        plan.decide(&copied_observation),
        Decision::Block(BlockReason::ExplicitBlock)
    );
}
