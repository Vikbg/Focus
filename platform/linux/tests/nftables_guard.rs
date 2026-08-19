use std::{fs, path::PathBuf};

use focus_linux::{
    FOCUS_NFT_BLOCKED_IPV4_SET, FOCUS_NFT_BLOCKED_IPV6_SET, FOCUS_NFT_FAMILY,
    FOCUS_NFT_OUTPUT_CHAIN, FOCUS_NFT_TABLE, FocusNftablesControl, FocusNftablesError,
    FocusNftablesTransaction, SystemNftablesControl, reload_focus_nftables,
    remove_focus_nftables,
};

#[derive(Debug)]
struct RecordingNftablesControl {
    unrelated_table: String,
    focus_table: Option<String>,
    replace_calls: usize,
    verify_calls: usize,
    remove_calls: usize,
    fail_replace: bool,
    fail_verify: bool,
    fail_remove: bool,
}

impl FocusNftablesControl for RecordingNftablesControl {
    fn replace_focus_table(
        &mut self,
        transaction: &FocusNftablesTransaction,
    ) -> Result<(), FocusNftablesError> {
        self.replace_calls += 1;
        if self.fail_replace {
            return Err(FocusNftablesError::ApplyFailed);
        }
        self.focus_table = Some(transaction.render());
        Ok(())
    }

    fn verify_focus_table(
        &mut self,
        transaction: &FocusNftablesTransaction,
    ) -> Result<(), FocusNftablesError> {
        self.verify_calls += 1;
        if self.fail_verify || self.focus_table.as_deref() != Some(transaction.render().as_str()) {
            return Err(FocusNftablesError::VerificationFailed);
        }
        Ok(())
    }

    fn remove_focus_table(&mut self) -> Result<(), FocusNftablesError> {
        self.remove_calls += 1;
        if self.fail_remove {
            return Err(FocusNftablesError::ApplyFailed);
        }
        self.focus_table = None;
        Ok(())
    }
}

fn recording_control() -> RecordingNftablesControl {
    RecordingNftablesControl {
        unrelated_table: "keep-unrelated-rule".to_owned(),
        focus_table: Some("old-focus-state".to_owned()),
        replace_calls: 0,
        verify_calls: 0,
        remove_calls: 0,
        fail_replace: false,
        fail_verify: false,
        fail_remove: false,
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn focus_transaction_is_namespaced_and_never_flushes_the_global_ruleset() {
    let transaction = FocusNftablesTransaction::new();
    let script = transaction.replacement_script();

    assert_eq!(FOCUS_NFT_FAMILY, "inet");
    assert_eq!(FOCUS_NFT_TABLE, "focus");
    assert!(script.starts_with("destroy table inet focus\n"));
    assert!(script.contains("table inet focus {"));
    assert!(!script.contains("flush ruleset"));
    assert!(!script.contains("delete ruleset"));
}

#[test]
fn focus_transaction_declares_fixed_chain_and_sets() {
    let transaction = FocusNftablesTransaction::new();
    let script = transaction.render();

    assert_eq!(FOCUS_NFT_OUTPUT_CHAIN, "output");
    assert_eq!(FOCUS_NFT_BLOCKED_IPV4_SET, "blocked_ipv4");
    assert_eq!(FOCUS_NFT_BLOCKED_IPV6_SET, "blocked_ipv6");
    assert!(script.contains("set blocked_ipv4"));
    assert!(script.contains("type ipv4_addr"));
    assert!(script.contains("set blocked_ipv6"));
    assert!(script.contains("type ipv6_addr"));
    assert!(script.contains("chain output"));
    assert!(script.contains("hook output"));
}

#[test]
fn focus_reload_only_targets_focus_owned_objects() {
    let transaction = FocusNftablesTransaction::new();

    for command in transaction.commands() {
        assert_eq!(command.family(), FOCUS_NFT_FAMILY);
        assert_eq!(command.table(), FOCUS_NFT_TABLE);
    }
}

#[test]
fn production_control_has_no_caller_selected_table_scope() {
    let _control = SystemNftablesControl::default();
}

#[test]
fn focus_reload_preserves_unrelated_firewall_state_and_verifies_after_replace() {
    let mut control = recording_control();
    let transaction = FocusNftablesTransaction::new();

    reload_focus_nftables(&mut control, &transaction).unwrap();

    assert_eq!(control.unrelated_table, "keep-unrelated-rule");
    assert_eq!(control.focus_table, Some(transaction.render()));
    assert_eq!(control.replace_calls, 1);
    assert_eq!(control.verify_calls, 1);
}

#[test]
fn focus_reload_apply_failure_is_fail_closed_before_verification() {
    let mut control = recording_control();
    control.fail_replace = true;
    let transaction = FocusNftablesTransaction::new();

    assert_eq!(
        reload_focus_nftables(&mut control, &transaction),
        Err(FocusNftablesError::ApplyFailed)
    );
    assert_eq!(control.unrelated_table, "keep-unrelated-rule");
    assert_eq!(control.focus_table.as_deref(), Some("old-focus-state"));
    assert_eq!(control.replace_calls, 1);
    assert_eq!(control.verify_calls, 0);
}

#[test]
fn focus_reload_verification_failure_is_fail_closed() {
    let mut control = recording_control();
    control.fail_verify = true;
    let transaction = FocusNftablesTransaction::new();

    assert_eq!(
        reload_focus_nftables(&mut control, &transaction),
        Err(FocusNftablesError::VerificationFailed)
    );
    assert_eq!(control.unrelated_table, "keep-unrelated-rule");
    assert_eq!(control.focus_table, Some(transaction.render()));
    assert_eq!(control.replace_calls, 1);
    assert_eq!(control.verify_calls, 1);
}

#[test]
fn focus_remove_is_idempotent_and_preserves_unrelated_firewall_state() {
    let mut control = recording_control();

    remove_focus_nftables(&mut control).unwrap();
    remove_focus_nftables(&mut control).unwrap();

    assert_eq!(control.unrelated_table, "keep-unrelated-rule");
    assert_eq!(control.focus_table, None);
    assert_eq!(control.remove_calls, 2);
}

#[test]
fn focus_remove_failure_is_fail_closed() {
    let mut control = recording_control();
    control.fail_remove = true;

    assert_eq!(
        remove_focus_nftables(&mut control),
        Err(FocusNftablesError::ApplyFailed)
    );
    assert_eq!(control.unrelated_table, "keep-unrelated-rule");
    assert_eq!(control.focus_table.as_deref(), Some("old-focus-state"));
    assert_eq!(control.remove_calls, 1);
}

#[test]
fn task24_requires_real_nftables_live_gate() {
    let root = repo_root();
    let live = fs::read_to_string(root.join("platform/linux/tests/nftables_live.rs"))
        .expect("Task 24 nftables live test file is missing");
    let workflow = fs::read_to_string(root.join(".github/workflows/nftables-live.yml"))
        .expect("Task 24 nftables live CI workflow is missing");

    for marker in [
        "focus_reload_preserves_real_unrelated_table_and_replaces_stale_focus_state",
        "unrelated_fixture",
        "stale_focus_fixture",
        "SystemNftablesControl::default()",
        "reload_focus_nftables",
    ] {
        assert!(
            live.contains(marker),
            "nftables live test is missing {marker}"
        );
    }

    for marker in [
        "name: Nftables live",
        "runs-on: ubuntu-24.04",
        "systemd-detect-virt --vm",
        "sudo apt-get install --yes nftables",
        "--test nftables_live",
        "--ignored",
        "--nocapture",
    ] {
        assert!(
            workflow.contains(marker),
            "nftables live workflow is missing {marker}"
        );
    }
}
