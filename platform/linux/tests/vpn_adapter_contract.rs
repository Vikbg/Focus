use std::path::{Path, PathBuf};

use focus_linux::{
    OpenVpnAdapter, OpenVpnCommandControl, OpenVpnProfile, OpenVpnUnitName, PrivilegeBrokerError,
    VpnAdapter, WireGuardCommandControl, WireGuardProfile, WireGuardVpnActionControl,
};

#[derive(Debug, Default)]
struct RecordingWireGuardCommandControl {
    ups: Vec<PathBuf>,
}

impl WireGuardCommandControl for RecordingWireGuardCommandControl {
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError> {
        Ok(true)
    }

    fn config_is_trusted(&self, _config: &Path) -> Result<bool, PrivilegeBrokerError> {
        Ok(true)
    }

    fn bring_up(&mut self, config: &Path) -> Result<(), PrivilegeBrokerError> {
        self.ups.push(config.to_path_buf());
        Ok(())
    }

    fn bring_down(&mut self, _config: &Path) -> Result<(), PrivilegeBrokerError> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct RecordingOpenVpnCommandControl {
    starts: Vec<(String, PathBuf)>,
}

impl OpenVpnCommandControl for RecordingOpenVpnCommandControl {
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError> {
        Ok(true)
    }

    fn config_is_trusted(&self, _config: &Path) -> Result<bool, PrivilegeBrokerError> {
        Ok(true)
    }

    fn start_service(
        &mut self,
        unit: &OpenVpnUnitName,
        config: &Path,
    ) -> Result<(), PrivilegeBrokerError> {
        self.starts
            .push((unit.as_str().to_owned(), config.to_path_buf()));
        Ok(())
    }

    fn stop_service(&mut self, _unit: &OpenVpnUnitName) -> Result<(), PrivilegeBrokerError> {
        Ok(())
    }
}

fn assert_vpn_adapter<T: VpnAdapter>() {}

#[test]
fn wireguard_implements_provider_neutral_vpn_adapter_contract() {
    assert_vpn_adapter::<WireGuardVpnActionControl<RecordingWireGuardCommandControl>>();

    let config = PathBuf::from("/etc/focus/wireguard/study.conf");
    let profile = WireGuardProfile::new(41, config.clone());
    let mut adapter =
        WireGuardVpnActionControl::new([profile], RecordingWireGuardCommandControl::default());

    assert_eq!(adapter.connect(41), Ok(()));
    assert_eq!(adapter.command_control().ups, vec![config]);
    assert_eq!(
        adapter.connect(99),
        Err(PrivilegeBrokerError::ActionNotApproved)
    );
}

#[test]
fn openvpn_implements_provider_neutral_vpn_adapter_contract() {
    assert_vpn_adapter::<OpenVpnAdapter<RecordingOpenVpnCommandControl>>();

    let config = PathBuf::from("/etc/focus/openvpn/study.ovpn");
    let profile = OpenVpnProfile::new(51, config.clone());
    let mut adapter = OpenVpnAdapter::new([profile], RecordingOpenVpnCommandControl::default());

    assert_eq!(VpnAdapter::connect(&mut adapter, 51), Ok(()));
    assert_eq!(
        adapter.command_control().starts,
        vec![("focus-openvpn-51.service".to_owned(), config)]
    );
    assert_eq!(
        VpnAdapter::connect(&mut adapter, 99),
        Err(PrivilegeBrokerError::ActionNotApproved)
    );
}
