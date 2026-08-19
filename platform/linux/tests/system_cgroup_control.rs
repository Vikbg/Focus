use std::{fs, path::Path};

use focus_linux::{
    FOCUS_CGROUP_ROOT, FocusCgroupClass, FocusCgroupControl, SystemCgroupControl,
};

fn repo_source() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/system_cgroup_control.rs");
    fs::read_to_string(path).expect("system cgroup control source is missing")
}

#[test]
fn production_cgroup_control_uses_only_the_fixed_focus_root() {
    let control = SystemCgroupControl::default();

    assert_eq!(FOCUS_CGROUP_ROOT, "/sys/fs/cgroup/focus");
    assert_eq!(control.root(), Path::new(FOCUS_CGROUP_ROOT));
    assert_eq!(
        control.class_path(FocusCgroupClass::Browser),
        Path::new("/sys/fs/cgroup/focus/browser")
    );
    assert_eq!(
        control.class_path(FocusCgroupClass::Blocked),
        Path::new("/sys/fs/cgroup/focus/blocked")
    );
}

#[test]
fn production_control_implements_the_typed_cgroup_authority() {
    fn assert_control<C: FocusCgroupControl>() {}
    assert_control::<SystemCgroupControl>();
}

#[test]
fn production_api_exposes_no_caller_selected_cgroup_root() {
    let source = repo_source();

    assert!(!source.contains("pub fn with_root"));
    assert!(!source.contains("pub fn new(root"));
    assert!(!source.contains("pub fn new(root:"));
    assert!(!source.contains("pub root:"));
}
