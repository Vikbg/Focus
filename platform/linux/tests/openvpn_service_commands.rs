use std::{fs, path::PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn production_openvpn_control_uses_fixed_noninteractive_systemd_lifecycle_commands() {
    let source = fs::read_to_string(repo_root().join("platform/linux/src/openvpn_vpn.rs"))
        .expect("OpenVPN production control source is missing");

    for marker in [
        "process::{Command, Stdio}",
        "fn run_start_command",
        "fn verify_service_active",
        "fn run_stop_command",
        "\"--no-ask-password\"",
        "\"--unit\"",
        "\"--property=Type=exec\"",
        "\"--collect\"",
        "\"--\"",
        "\"--config\"",
        "\"--quiet\"",
        "\"is-active\"",
        "\"stop\"",
        "Stdio::null()",
    ] {
        assert!(
            source.contains(marker),
            "OpenVPN production lifecycle is missing fixed command marker {marker}"
        );
    }

    for forbidden in [
        "Command::new(\"sh\")",
        "Command::new(\"/bin/sh\")",
        "Command::new(\"bash\")",
        "Command::new(\"/bin/bash\")",
        "sh -c",
        "bash -c",
    ] {
        assert!(
            !source.contains(forbidden),
            "OpenVPN lifecycle must never use a shell: {forbidden}"
        );
    }
}
