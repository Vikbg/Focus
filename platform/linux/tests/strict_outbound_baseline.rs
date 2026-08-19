use focus_linux::{FOCUS_NFT_FAMILY, FOCUS_NFT_TABLE, FocusNftablesTransaction};

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
