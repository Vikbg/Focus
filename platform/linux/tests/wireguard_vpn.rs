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

#[test]
fn approved_wireguard_profile_disconnects_exact_registered_config() {
    let config = PathBuf::from("/etc/focus/wireguard/study.conf");
    let command = RecordingWireGuardCommandControl {
        trusted_executor: true,
        trusted_configs: vec![config.clone()],
        ..RecordingWireGuardCommandControl::default()
    };
    let profile = WireGuardProfile::new(41, config.clone());
    let mut control = WireGuardVpnActionControl::new([profile], command);

    assert_eq!(control.disconnect_vpn(41), Ok(()));
    assert_eq!(control.command_control().downs, vec![config]);
    assert!(control.command_control().ups.is_empty());
}

#[test]
fn unknown_wireguard_profile_is_denied_before_executor_trust_is_considered() {
    let config = PathBuf::from("/etc/focus/wireguard/study.conf");
    let command = RecordingWireGuardCommandControl {
        trusted_executor: false,
        trusted_configs: vec![config.clone()],
        ..RecordingWireGuardCommandControl::default()
    };
    let profile = WireGuardProfile::new(41, config);
    let mut control = WireGuardVpnActionControl::new([profile], command);

    assert_eq!(
        control.connect_vpn(99),
        Err(PrivilegeBrokerError::ActionNotApproved)
    );
    assert!(control.command_control().ups.is_empty());
    assert!(control.command_control().downs.is_empty());
}

#[test]
fn duplicate_wireguard_profile_id_is_denied_as_ambiguous() {
    let first = PathBuf::from("/etc/focus/wireguard/study.conf");
    let second = PathBuf::from("/etc/focus/wireguard/alternate.conf");
    let command = RecordingWireGuardCommandControl {
        trusted_executor: true,
        trusted_configs: vec![first.clone(), second.clone()],
        ..RecordingWireGuardCommandControl::default()
    };
    let mut control = WireGuardVpnActionControl::new(
        [
            WireGuardProfile::new(41, first),
            WireGuardProfile::new(41, second),
        ],
        command,
    );

    assert_eq!(
        control.connect_vpn(41),
        Err(PrivilegeBrokerError::ActionNotApproved)
    );
    assert!(control.command_control().ups.is_empty());
    assert!(control.command_control().downs.is_empty());
}

#[test]
fn untrusted_wireguard_executor_is_denied_before_command_execution() {
    let config = PathBuf::from("/etc/focus/wireguard/study.conf");
    let command = RecordingWireGuardCommandControl {
        trusted_executor: false,
        trusted_configs: vec![config.clone()],
        ..RecordingWireGuardCommandControl::default()
    };
    let profile = WireGuardProfile::new(41, config);
    let mut control = WireGuardVpnActionControl::new([profile], command);

    assert_eq!(
        control.connect_vpn(41),
        Err(PrivilegeBrokerError::UnsafeExecutor)
    );
    assert!(control.command_control().ups.is_empty());
    assert!(control.command_control().downs.is_empty());
}

#[test]
fn untrusted_wireguard_config_is_denied_before_command_execution() {
    let config = PathBuf::from("/etc/focus/wireguard/study.conf");
    let command = RecordingWireGuardCommandControl {
        trusted_executor: true,
        ..RecordingWireGuardCommandControl::default()
    };
    let profile = WireGuardProfile::new(41, config);
    let mut control = WireGuardVpnActionControl::new([profile], command);

    assert_eq!(
        control.connect_vpn(41),
        Err(PrivilegeBrokerError::ActionNotApproved)
    );
    assert!(control.command_control().ups.is_empty());
    assert!(control.command_control().downs.is_empty());
}
