use std::{
    fs,
    path::{Path, PathBuf},
};

use focus_linux::{
    OpenVpnCommandControl, OpenVpnUnitName, PrivilegeBrokerError, SystemOpenVpnCommandControl,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn assert_openvpn_command_control<T: OpenVpnCommandControl + Default>() {}

#[derive(Default)]
struct TypedUnitContract;

impl OpenVpnCommandControl for TypedUnitContract {
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError> {
        Ok(true)
    }

    fn config_is_trusted(&self, _config: &Path) -> Result<bool, PrivilegeBrokerError> {
        Ok(true)
    }

    fn start_service(
        &mut self,
        _unit: &OpenVpnUnitName,
        _config: &Path,
    ) -> Result<(), PrivilegeBrokerError> {
        Ok(())
    }

    fn stop_service(&mut self, _unit: &OpenVpnUnitName) -> Result<(), PrivilegeBrokerError> {
        Ok(())
    }
}

#[test]
fn production_openvpn_control_implements_narrow_command_contract() {
    assert_openvpn_command_control::<SystemOpenVpnCommandControl>();
    let _control = SystemOpenVpnCommandControl::default();
}

#[test]
fn openvpn_command_contract_uses_typed_unit_identity() {
    assert_openvpn_command_control::<TypedUnitContract>();
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

#[test]
fn openvpn_unit_name_is_derived_deterministically_from_vpn_id() {
    let unit = OpenVpnUnitName::from_id(42);
    assert_eq!(unit.as_str(), "focus-openvpn-42.service");

    let max = OpenVpnUnitName::from_id(u128::MAX);
    assert_eq!(
        max.as_str(),
        "focus-openvpn-340282366920938463463374607431768211455.service"
    );
}
