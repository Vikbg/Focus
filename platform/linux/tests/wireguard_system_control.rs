use std::{fs, path::PathBuf};

use focus_linux::{SystemWireGuardCommandControl, WireGuardCommandControl};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn assert_wireguard_command_control<T: WireGuardCommandControl + Default>() {}

#[test]
fn production_wireguard_control_implements_narrow_command_contract() {
    assert_wireguard_command_control::<SystemWireGuardCommandControl>();
    let _control = SystemWireGuardCommandControl::default();
}

#[test]
fn production_wireguard_control_uses_only_fixed_trusted_wg_quick_and_config_scope() {
    let source = fs::read_to_string(repo_root().join("platform/linux/src/wireguard_vpn.rs"))
        .expect("WireGuard production control source is missing");

    for marker in [
        "WG_QUICK_CANDIDATES",
        "\"/usr/bin/wg-quick\"",
        "\"/usr/sbin/wg-quick\"",
        "Command::new",
        "\"up\"",
        "\"down\"",
        "symlink_metadata",
        "MetadataExt",
        "PermissionsExt",
        "fs::read_to_string",
        "trusted_config_root_metadata",
        "FOCUS_WIREGUARD_CONFIG_ROOT",
        "safe_config_contents",
    ] {
        assert!(
            source.contains(marker),
            "WireGuard production control is missing security marker {marker}"
        );
    }
}
