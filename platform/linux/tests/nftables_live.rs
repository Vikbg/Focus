use std::{
    env,
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

use focus_linux::{FocusNftablesTransaction, SystemNftablesControl, reload_focus_nftables};

const FOCUS_TABLE: &str = "focus";
const UNRELATED_TABLE: &str = "unrelated_fixture";
const STALE_FOCUS_CHAIN: &str = "stale_focus_fixture";
const NFT_CANDIDATES: [&str; 2] = ["/usr/sbin/nft", "/usr/bin/nft"];

fn nft_executable() -> &'static str {
    NFT_CANDIDATES
        .into_iter()
        .find(|candidate| Path::new(candidate).is_file())
        .expect("Task 24 live fixture requires nft")
}

fn run_nft_script(script: &str) -> Output {
    let mut child = Command::new(nft_executable())
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start nft");

    child
        .stdin
        .take()
        .expect("nft stdin is unavailable")
        .write_all(script.as_bytes())
        .expect("failed to write nft transaction");

    child.wait_with_output().expect("failed to wait for nft")
}

fn require_nft_script(script: &str) {
    let output = run_nft_script(script);
    assert!(
        output.status.success(),
        "nft transaction failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn destroy_fixture_table(table: &str) {
    let _ = run_nft_script(&format!("destroy table inet {table}\n"));
}

fn list_table(table: &str) -> String {
    let output = Command::new(nft_executable())
        .args(["list", "table", "inet", table])
        .output()
        .expect("failed to list nft table");
    assert!(
        output.status.success(),
        "failed to list nft table {table}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("nft table output must be UTF-8")
}

struct FixtureCleanup;

impl Drop for FixtureCleanup {
    fn drop(&mut self) {
        destroy_fixture_table(FOCUS_TABLE);
        destroy_fixture_table(UNRELATED_TABLE);
    }
}

#[test]
#[ignore = "requires disposable root VM with nftables"]
fn focus_reload_preserves_real_unrelated_table_and_replaces_stale_focus_state() {
    assert_eq!(env::var("FOCUS_VM_SCENARIO").as_deref(), Ok("nftables-live"));

    let uid = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .expect("failed to query fixture uid");
    assert!(uid.status.success());
    assert_eq!(String::from_utf8_lossy(&uid.stdout).trim(), "0");

    let _cleanup = FixtureCleanup;
    destroy_fixture_table(FOCUS_TABLE);
    destroy_fixture_table(UNRELATED_TABLE);

    require_nft_script(
        "table inet unrelated_fixture {\n\
         \tset keep {\n\
         \t\ttype ipv4_addr\n\
         \t\telements = { 192.0.2.1 }\n\
         \t}\n\
         }\n\
         table inet focus {\n\
         \tchain stale_focus_fixture {\n\
         \t}\n\
         }\n",
    );

    let unrelated_before = list_table(UNRELATED_TABLE);
    assert!(list_table(FOCUS_TABLE).contains(STALE_FOCUS_CHAIN));

    let transaction = FocusNftablesTransaction::new();
    let mut control = SystemNftablesControl::default();
    reload_focus_nftables(&mut control, &transaction).expect("first Focus reload failed");

    assert_eq!(list_table(UNRELATED_TABLE), unrelated_before);
    let first_focus_state = list_table(FOCUS_TABLE);
    assert!(!first_focus_state.contains(STALE_FOCUS_CHAIN));
    assert!(first_focus_state.contains("blocked_ipv4"));
    assert!(first_focus_state.contains("blocked_ipv6"));
    assert!(first_focus_state.contains("chain output"));

    require_nft_script("add chain inet focus stale_focus_fixture\n");
    assert!(list_table(FOCUS_TABLE).contains(STALE_FOCUS_CHAIN));

    reload_focus_nftables(&mut control, &transaction).expect("second Focus reload failed");

    assert_eq!(list_table(UNRELATED_TABLE), unrelated_before);
    let second_focus_state = list_table(FOCUS_TABLE);
    assert!(!second_focus_state.contains(STALE_FOCUS_CHAIN));
    assert_eq!(second_focus_state, first_focus_state);
}
