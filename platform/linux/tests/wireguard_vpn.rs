use std::path::{Path, PathBuf};

use focus_linux::{
    PrivilegeBrokerError, VpnActionControl, WireGuardCommandControl, WireGuardProfile,
    WireGuardVpnActionControl,
};

#[derive(Debug, Default)]
struct RecordingWireGuardCommandControl {
    trusted_executor: bool,
    trusted_configs: Vec<PathBuf>,
    ups: Vec<PathBuf>,
    downs: Vec<PathBuf>,
}

impl WireGuardCommandControl for RecordingWireGuardCommandControl {
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError> {
        Ok(self.trusted_executor)
    }

    fn config_is_trusted(&self, config: &Path) -> Result<bool, PrivilegeBrokerError> {
        Ok(self.trusted_configs.iter().any(|trusted| trusted == config))
    }

    fn bring_up(&mut self, config: &Path) -> Result<(), PrivilegeBrokerError> {
        self.ups.push(config.to_path_buf());
        Ok(())
    }

    fn bring_down(&mut self, config: &Path) -> Result<(), PrivilegeBrokerError> {
        self.downs.push(config.to_path_buf());
        Ok(())
    }
}

#[test]
fn approved_wireguard_profile_connects_exact_registered_config() {
    let config = PathBuf::from("/etc/focus/wireguard/study.conf");
    let command = RecordingWireGuardCommandControl {
        trusted_executor: true,
        trusted_configs: vec![config.clone()],
        ..RecordingWireGuardCommandControl::default()
    };
    let profile = WireGuardProfile::new(41, config.clone());
    let mut control = WireGuardVpnActionControl::new([profile], command);

    assert_eq!(control.connect_vpn(41), Ok(()));
    assert_eq!(control.command_control().ups, vec![config]);
    assert!(control.command_control().downs.is_empty());
}
