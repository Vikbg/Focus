use std::{fs, path::PathBuf};

use focus_linux::{FOCUS_NFT_FAMILY, FOCUS_NFT_TABLE, FocusNftablesTransaction};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn strict_outbound_baseline_defaults_to_drop() {
    let transaction = FocusNftablesTransaction::strict_outbound();
    let script = transaction.render();

    assert!(script.contains("chain output"));
    assert!(script.contains("policy drop"));
    assert!(!script.contains("policy accept"));
}

#[test]
fn strict_outbound_baseline_stays_inside_focus_owned_table() {
    let transaction = FocusNftablesTransaction::strict_outbound();

    for command in transaction.commands() {
        assert_eq!(command.family(), FOCUS_NFT_FAMILY);
        assert_eq!(command.table(), FOCUS_NFT_TABLE);
    }
}

#[test]
fn task25_requires_real_strict_outbound_traffic_gate() {
    let root = repo_root();
    let live = fs::read_to_string(root.join("platform/linux/tests/strict_outbound_live.rs"))
        .expect("Task 25 strict outbound live test file is missing");
    let workflow = fs::read_to_string(root.join(".github/workflows/strict-outbound-live.yml"))
        .expect("Task 25 strict outbound live CI workflow is missing");

    for marker in [
        "ProductionNetworkGuard",
        "curl",
        "wget",
        "nc",
        "arm()",
        "verify()",
        "disarm()",
        "strict-outbound-live",
    ] {
        assert!(
            live.contains(marker),
            "strict outbound live test is missing {marker}"
        );
    }

    for marker in [
        "name: Strict outbound live",
        "runs-on: ubuntu-24.04",
        "systemd-detect-virt --vm",
        "netcat-openbsd",
        "--test strict_outbound_live",
        "--ignored",
        "--nocapture",
    ] {
        assert!(
            workflow.contains(marker),
            "strict outbound live workflow is missing {marker}"
        );
    }
}
