use focus_linux::{FocusNftablesTransaction, FOCUS_NFT_FAMILY, FOCUS_NFT_TABLE};

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
