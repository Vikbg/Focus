use std::{fs, path::PathBuf};

fn live_workflow_source() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows/ebpf-egress-live.yml");
    fs::read_to_string(path).expect("Task 27 eBPF egress live workflow is missing")
}

#[test]
fn task27_live_gate_builds_installs_and_runs_real_egress_proof() {
    let workflow = live_workflow_source();

    assert!(workflow.contains("systemd-detect-virt --vm"));
    assert!(workflow.contains("nightly-2026-08-19"));
    assert!(workflow.contains("bpf-linker-x86_64-unknown-linux-musl.tar.zst"));
    assert!(workflow.contains("--target bpfel-unknown-none"));
    assert!(workflow.contains("--release"));
    assert!(workflow.contains("--locked"));
    assert!(workflow.contains("/usr/lib/focus/focus-egress-ebpf.o"));
    assert!(workflow.contains("FOCUS_VM_SCENARIO=ebpf-egress-live"));
    assert!(workflow.contains("--test ebpf_egress_live"));
    assert!(workflow.contains("--ignored"));
    assert!(workflow.contains("--nocapture"));
}
