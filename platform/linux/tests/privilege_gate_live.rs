use std::process::Command;

#[test]
#[ignore = "requires disposable root VM with sudo and PAM"]
fn privilege_gate_blocks_unrestricted_sudo_paths() {
    assert_eq!(
        std::env::var("FOCUS_VM_SCENARIO").as_deref(),
        Ok("privilege-gate"),
        "live privilege fixture must run only through the disposable VM harness"
    );
    assert!(
        Command::new("systemd-detect-virt")
            .arg("--vm")
            .status()
            .unwrap()
            .success(),
        "live privilege fixture requires a virtual machine"
    );
    let uid = Command::new("id").arg("-u").output().unwrap();
    assert!(uid.status.success());
    assert_eq!(String::from_utf8(uid.stdout).unwrap().trim(), "0");

    panic!("production privilege guard is not implemented");
}
