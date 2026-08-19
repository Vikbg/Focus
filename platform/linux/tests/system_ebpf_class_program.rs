use std::{
    fs,
    path::{Path, PathBuf},
};

use focus_linux::{
    EgressClassProgramControl, FOCUS_CGROUP_ROOT, FOCUS_EBPF_OBJECT_PATH, FocusCgroupClass,
    SystemEgressClassProgramControl,
};

fn repo_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/system_ebpf_class_program.rs");
    fs::read_to_string(path).expect("system eBPF class program source is missing")
}

#[test]
fn production_ebpf_control_uses_only_fixed_focus_paths() {
    let control = SystemEgressClassProgramControl::default();

    assert_eq!(FOCUS_EBPF_OBJECT_PATH, "/usr/lib/focus/focus-egress-ebpf.o");
    assert_eq!(control.object_path(), Path::new(FOCUS_EBPF_OBJECT_PATH));
    assert_eq!(FOCUS_CGROUP_ROOT, "/sys/fs/cgroup/focus");
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
fn production_ebpf_control_implements_the_typed_program_authority() {
    fn assert_control<C: EgressClassProgramControl>() {}
    assert_control::<SystemEgressClassProgramControl>();
}

#[test]
fn production_verification_requires_a_live_cgroup_kernel_link() {
    let source = repo_source();

    assert!(source.contains("loaded_links()"));
    assert!(source.contains("LinkType::Cgroup"));
    assert!(source.contains("program_id() == expected_program_id"));
}

#[test]
fn production_ebpf_api_exposes_no_caller_selected_paths() {
    let source = repo_source();

    assert!(!source.contains("pub fn with_object_path"));
    assert!(!source.contains("pub fn with_cgroup_root"));
    assert!(!source.contains("pub fn new(object_path"));
    assert!(!source.contains("pub fn new(cgroup_root"));
    assert!(!source.contains("pub object_path:"));
    assert!(!source.contains("pub cgroup_root:"));
}
