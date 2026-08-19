use std::path::{Path, PathBuf};

use focus_linux::{
    PrivilegeBrokerError, VpnAdapter, WireGuardCommandControl, WireGuardProfile,
    WireGuardVpnActionControl,
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
