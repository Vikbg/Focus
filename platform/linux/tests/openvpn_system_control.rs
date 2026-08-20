use std::{fs, path::PathBuf};

use focus_linux::{OpenVpnCommandControl, SystemOpenVpnCommandControl};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn assert_openvpn_command_control<T: OpenVpnCommandControl + Default>() {}

#[test]
fn production_openvpn_control_implements_narrow_command_contract() {
    assert_openvpn_command_control::<SystemOpenVpnCommandControl>();
    let _control = SystemOpenVpnCommandControl::default();
}

#[test]
fn production_openvpn_control_uses_only_fixed_system_executors_and_focus_config_scope() {
    let source = fs::read_to_string(repo_root().join("platform/linux/src/openvpn_vpn.rs"))
        .expect("OpenVPN production control source is missing");

    for marker in [
        "OPENVPN_CANDIDATES",
        "\"/usr/sbin/openvpn\"",
        "\"/usr/bin/openvpn\"",
        "SYSTEMD_RUN_CANDIDATES",
        "\"/usr/bin/systemd-run\"",
        "\"/bin/systemd-run\"",
        "SYSTEMCTL_CANDIDATES",
        "\"/usr/bin/systemctl\"",
        "\"/bin/systemctl\"",
        "FOCUS_OPENVPN_CONFIG_ROOT",
        "\"/etc/focus/openvpn\"",
    ] {
        assert!(
            source.contains(marker),
            "OpenVPN production control is missing fixed-boundary marker {marker}"
        );
    }
}
