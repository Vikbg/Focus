use std::{
    fs,
    future::Future,
    os::unix::fs::PermissionsExt,
    path::Path,
    pin::pin,
    process::{Command, Output},
    task::{Context, Poll, Waker},
};

use focus_linux::{PrivilegeGuardControl, ProductionLinuxBackend, ProductionPrivilegeGuard};
use focus_platform::{PlatformBackend, PrivilegedAction};

const FIXTURE_USER: &str = "focuspriv";
const SUDOERS_PATH: &str = "/etc/sudoers.d/focus-task21";
const PAM_PATH: &str = "/etc/pam.d/sudo";
const DENY_LIST_PATH: &str = "/var/lib/focus/privilege-deny-users";
const SERVICE_PATH: &str = "/etc/systemd/system/focusd.service";
const DOCKER_SERVICE_PATH: &str = "/etc/systemd/system/docker.service";
const PAM_RULE: &str = "account requisite pam_listfile.so item=user sense=deny file=/var/lib/focus/privilege-deny-users onerr=fail";
const NFT_TABLE: &str = "focus_task21_fixture";

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("Linux privilege fixture futures must resolve immediately"),
    }
}

fn command_status(program: &str, arguments: &[&str]) -> bool {
    Command::new(program)
        .args(arguments)
        .status()
        .is_ok_and(|status| status.success())
}

fn require_command(command: &str) {
    assert!(
        command_status("sh", &["-c", &format!("command -v {command} >/dev/null")]),
        "privilege VM fixture requires {command}"
    );
}

fn run_sudo_as(arguments: &[&str]) -> Output {
    let mut command = Command::new("runuser");
    command
        .args(["-u", FIXTURE_USER, "--", "sudo", "-n"])
        .args(arguments)
        .env("LC_ALL", "C");
    command.output().unwrap()
}

fn assert_sudo_blocked(arguments: &[&str]) {
    let output = run_sudo_as(arguments);
    assert!(
        !output.status.success(),
        "sudo bypass unexpectedly succeeded: {}",
        arguments.join(" ")
    );
}

fn install_fixture_user() -> u32 {
    let _ = Command::new("userdel").args(["-r", FIXTURE_USER]).status();
    assert!(command_status(
        "useradd",
        &["--create-home", "--shell", "/bin/bash", FIXTURE_USER]
    ));
    let output = Command::new("id")
        .args(["-u", FIXTURE_USER])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

fn install_sudo_fixture() -> String {
    let original_pam = fs::read_to_string(PAM_PATH).unwrap();
    let mut pam = original_pam.clone();
    if !pam.lines().any(|line| line.trim() == PAM_RULE) {
        if !pam.ends_with('\n') {
            pam.push('\n');
        }
        pam.push_str(PAM_RULE);
        pam.push('\n');
        fs::write(PAM_PATH, pam).unwrap();
    }

    fs::write(
        SUDOERS_PATH,
        format!("{FIXTURE_USER} ALL=(ALL:ALL) NOPASSWD: ALL\n"),
    )
    .unwrap();
    fs::set_permissions(SUDOERS_PATH, fs::Permissions::from_mode(0o440)).unwrap();
    assert!(command_status("visudo", &["-cf", SUDOERS_PATH]));

    fs::create_dir_all("/var/lib/focus").unwrap();
    fs::write(DENY_LIST_PATH, "").unwrap();
    fs::set_permissions(DENY_LIST_PATH, fs::Permissions::from_mode(0o600)).unwrap();
    original_pam
}

fn install_service_fixture() {
    assert!(
        !Path::new(SERVICE_PATH).exists(),
        "disposable Task 21 VM must not contain a preinstalled focusd.service override"
    );
    assert!(
        !Path::new(DOCKER_SERVICE_PATH).exists(),
        "disposable Task 21 VM must not contain a preinstalled docker.service override"
    );
    fs::write(
        SERVICE_PATH,
        "[Unit]\nDescription=Focus Task 21 privilege fixture\n[Service]\nType=simple\nExecStart=/bin/sleep infinity\n",
    )
    .unwrap();
    fs::write(
        DOCKER_SERVICE_PATH,
        "[Unit]\nDescription=Focus Task 21 typed broker fixture\n[Service]\nType=simple\nExecStart=/bin/sleep infinity\n",
    )
    .unwrap();
    assert!(command_status("systemctl", &["daemon-reload"]));
    assert!(command_status("systemctl", &["start", "focusd"]));
    assert!(command_status("systemctl", &["stop", "docker.service"]));
    assert!(command_status(
        "systemctl",
        &["is-active", "--quiet", "focusd"]
    ));
    assert!(!command_status(
        "systemctl",
        &["is-active", "--quiet", "docker.service"]
    ));
}

fn install_nft_fixture() {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", NFT_TABLE])
        .status();
    assert!(command_status("nft", &["add", "table", "inet", NFT_TABLE]));
    assert!(command_status("nft", &["list", "table", "inet", NFT_TABLE]));
}

struct VmFixture {
    protected_uid: u32,
    original_pam: String,
}

impl VmFixture {
    fn new() -> Self {
        for command in [
            "id",
            "nft",
            "python3",
            "runuser",
            "sudo",
            "systemctl",
            "useradd",
            "userdel",
            "visudo",
        ] {
            require_command(command);
        }

        let protected_uid = install_fixture_user();
        let original_pam = install_sudo_fixture();
        install_service_fixture();
        install_nft_fixture();
        Self {
            protected_uid,
            original_pam,
        }
    }
}

impl Drop for VmFixture {
    fn drop(&mut self) {
        let _ = fs::write(DENY_LIST_PATH, "");
        let _ = fs::write(PAM_PATH, &self.original_pam);
        let _ = fs::remove_file(SUDOERS_PATH);
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", NFT_TABLE])
            .status();
        let _ = Command::new("systemctl")
            .args(["stop", "docker.service"])
            .status();
        let _ = Command::new("systemctl").args(["stop", "focusd"]).status();
        let _ = fs::remove_file(DOCKER_SERVICE_PATH);
        let _ = fs::remove_file(SERVICE_PATH);
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        let _ = Command::new("userdel").args(["-r", FIXTURE_USER]).status();
        for marker in [
            "/var/tmp/focus-task21-shell",
            "/var/tmp/focus-task21-bash",
            "/var/tmp/focus-task21-sh",
            "/var/tmp/focus-task21-python",
        ] {
            let _ = fs::remove_file(marker);
        }
    }
}

fn assert_required_bypasses_are_blocked() {
    assert_sudo_blocked(&["-s", "touch", "/var/tmp/focus-task21-shell"]);
    assert_sudo_blocked(&["bash", "-c", "touch /var/tmp/focus-task21-bash"]);
    assert_sudo_blocked(&["sh", "-c", "touch /var/tmp/focus-task21-sh"]);
    assert_sudo_blocked(&["systemctl", "stop", "focusd"]);
    assert_sudo_blocked(&["nft", "flush", "ruleset"]);
    assert_sudo_blocked(&[
        "python3",
        "-c",
        "from pathlib import Path; Path('/var/tmp/focus-task21-python').write_text('bypass')",
    ]);

    for marker in [
        "/var/tmp/focus-task21-shell",
        "/var/tmp/focus-task21-bash",
        "/var/tmp/focus-task21-sh",
        "/var/tmp/focus-task21-python",
    ] {
        assert!(
            !Path::new(marker).exists(),
            "blocked sudo command created {marker}"
        );
    }
    assert!(command_status(
        "systemctl",
        &["is-active", "--quiet", "focusd"]
    ));
    assert!(command_status("nft", &["list", "table", "inet", NFT_TABLE]));
}

fn assert_typed_broker_still_succeeds(protected_uid: u32) {
    let mut backend = ProductionLinuxBackend::for_uid(protected_uid);
    assert_eq!(
        block_on_ready(backend.execute_privileged_action(PrivilegedAction::DockerStart)),
        Ok(())
    );
    assert!(command_status(
        "systemctl",
        &["is-active", "--quiet", "docker.service"]
    ));
}

#[test]
fn fixture_pam_rule_precedes_sufficient_account_modules() {
    let original = "#%PAM-1.0\naccount sufficient pam_permit.so\n@include common-auth\n";
    let configured = pam_with_required_account_rule(original);
    let focus_rule = configured.find(PAM_RULE).unwrap();
    let sufficient_rule = configured.find("account sufficient pam_permit.so").unwrap();

    assert!(focus_rule < sufficient_rule);
}

#[test]
#[ignore = "requires disposable root VM with sudo and PAM"]
fn privilege_gate_blocks_unrestricted_sudo_paths() {
    assert_eq!(
        std::env::var("FOCUS_VM_SCENARIO").as_deref(),
        Ok("privilege-gate"),
        "live privilege fixture must run only through the disposable VM harness"
    );
    assert!(command_status("systemd-detect-virt", &["--vm"]));
    assert_eq!(nix::unistd::geteuid().as_raw(), 0);

    let fixture = VmFixture::new();
    assert!(
        run_sudo_as(&["true"]).status.success(),
        "fixture user must have unrestricted sudo before the Focus guard arms"
    );

    let mut guard = ProductionPrivilegeGuard::for_uid(fixture.protected_uid);
    guard.arm().unwrap();
    guard.verify().unwrap();
    assert_required_bypasses_are_blocked();
    assert_typed_broker_still_succeeds(fixture.protected_uid);
    guard.verify().unwrap();

    guard.disarm().unwrap();
    assert!(
        run_sudo_as(&["true"]).status.success(),
        "disarming the fixture must restore sudo availability"
    );
}
