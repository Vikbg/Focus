use std::{fs, path::PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn task27_requires_separate_policy_free_cgroup_egress_program() {
    let root = repo_root();
    let manifest =
        fs::read_to_string(root.join("platform/linux/ebpf/focus-egress-ebpf/Cargo.toml"))
            .expect("Task 27 eBPF crate manifest is missing");
    let program =
        fs::read_to_string(root.join("platform/linux/ebpf/focus-egress-ebpf/src/main.rs"))
            .expect("Task 27 eBPF program is missing");
    let workflow = fs::read_to_string(root.join(".github/workflows/ebpf-build.yml"))
        .expect("Task 27 eBPF build workflow is missing");

    for marker in ["aya-ebpf = \"=0.2.1\"", "[[bin]]", "focus-egress-ebpf"] {
        assert!(
            manifest.contains(marker),
            "eBPF manifest is missing {marker}"
        );
    }

    for marker in [
        "#![no_std]",
        "#![no_main]",
        "#[cgroup_skb(egress)]",
        "ALLOWED_IPV4_ENDPOINTS",
        "HashMap<u64, u8>",
        "unwrap_or(0)",
    ] {
        assert!(program.contains(marker), "eBPF program is missing {marker}");
    }

    for marker in [
        "name: eBPF build",
        "rust-src",
        "bpf-linker",
        "--target bpfel-unknown-none",
        "--locked",
    ] {
        assert!(
            workflow.contains(marker),
            "eBPF build workflow is missing {marker}"
        );
    }
}
