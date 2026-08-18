use focus_linux::{
    FOCUS_NFT_FAMILY, FOCUS_NFT_TABLE, FocusNftablesControl, FocusNftablesError,
    FocusNftablesTransaction, reload_focus_nftables,
};

#[derive(Debug)]
struct RecordingNftablesControl {
    unrelated_table: String,
    focus_table: String,
    replace_calls: usize,
    fail_replace: bool,
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
        self.focus_table = transaction.render();
        Ok(())
    }
}

#[test]
fn focus_transaction_is_namespaced_and_never_flushes_the_global_ruleset() {
    let transaction = FocusNftablesTransaction::new();
    let script = transaction.render();

    assert_eq!(FOCUS_NFT_FAMILY, "inet");
    assert_eq!(FOCUS_NFT_TABLE, "focus");
    assert!(script.contains("table inet focus"));
    assert!(!script.contains("flush ruleset"));
    assert!(!script.contains("delete ruleset"));
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
fn focus_reload_preserves_unrelated_firewall_state() {
    let mut control = RecordingNftablesControl {
        unrelated_table: "keep-unrelated-rule".to_owned(),
        focus_table: "old-focus-state".to_owned(),
        replace_calls: 0,
        fail_replace: false,
    };
    let transaction = FocusNftablesTransaction::new();

    reload_focus_nftables(&mut control, &transaction).unwrap();

    assert_eq!(control.unrelated_table, "keep-unrelated-rule");
    assert_eq!(control.focus_table, transaction.render());
    assert_eq!(control.replace_calls, 1);
}

#[test]
fn focus_reload_failure_is_fail_closed() {
    let mut control = RecordingNftablesControl {
        unrelated_table: "keep-unrelated-rule".to_owned(),
        focus_table: "old-focus-state".to_owned(),
        replace_calls: 0,
        fail_replace: true,
    };
    let transaction = FocusNftablesTransaction::new();

    assert_eq!(
        reload_focus_nftables(&mut control, &transaction),
        Err(FocusNftablesError::ApplyFailed)
    );
    assert_eq!(control.unrelated_table, "keep-unrelated-rule");
    assert_eq!(control.focus_table, "old-focus-state");
    assert_eq!(control.replace_calls, 1);
}
