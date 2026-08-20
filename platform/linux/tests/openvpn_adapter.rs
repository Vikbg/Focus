use std::path::{Path, PathBuf};

use focus_linux::{
    OpenVpnAdapter, OpenVpnCommandControl, OpenVpnProfile, PrivilegeBrokerError, VpnAdapter,
};

#[derive(Debug)]
struct RecordingOpenVpnCommandControl {
    trusted_executor: bool,
    trusted_config: bool,
    starts: Vec<(String, PathBuf)>,
    stops: Vec<String>,
}

impl Default for RecordingOpenVpnCommandControl {
    fn default() -> Self {
        Self {
            trusted_executor: true,
            trusted_config: true,
            starts: Vec::new(),
            stops: Vec::new(),
        }
    }
}

impl OpenVpnCommandControl for RecordingOpenVpnCommandControl {
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError> {
        Ok(self.trusted_executor)
    }

    fn config_is_trusted(&self, _config: &Path) -> Result<bool, PrivilegeBrokerError> {
        Ok(self.trusted_config)
    }

    fn start_service(&mut self, unit: &str, config: &Path) -> Result<(), PrivilegeBrokerError> {
        self.starts.push((unit.to_owned(), config.to_path_buf()));
        Ok(())
    }

    fn stop_service(&mut self, unit: &str) -> Result<(), PrivilegeBrokerError> {
        self.stops.push(unit.to_owned());
        Ok(())
    }
}

#[test]
fn approved_openvpn_profile_connects_exact_registered_config_under_deterministic_unit() {
    let config = PathBuf::from("/etc/focus/openvpn/study.ovpn");
    let profile = OpenVpnProfile::new(51, config.clone());
    let mut adapter = OpenVpnAdapter::new([profile], RecordingOpenVpnCommandControl::default());

    assert_eq!(adapter.connect(51), Ok(()));
    assert_eq!(
        adapter.command_control().starts,
        vec![("focus-openvpn-51.service".to_owned(), config)]
    );
    assert!(adapter.command_control().stops.is_empty());
}

#[test]
fn approved_openvpn_profile_disconnects_exact_deterministic_unit() {
    let config = PathBuf::from("/etc/focus/openvpn/study.ovpn");
    let profile = OpenVpnProfile::new(51, config);
    let mut adapter = OpenVpnAdapter::new([profile], RecordingOpenVpnCommandControl::default());

    assert_eq!(adapter.disconnect(51), Ok(()));
    assert_eq!(
        adapter.command_control().stops,
        vec!["focus-openvpn-51.service".to_owned()]
    );
    assert!(adapter.command_control().starts.is_empty());
}

#[test]
fn duplicate_openvpn_profile_id_is_denied_as_ambiguous() {
    let first = PathBuf::from("/etc/focus/openvpn/study.ovpn");
    let second = PathBuf::from("/etc/focus/openvpn/alternate.ovpn");
    let mut adapter = OpenVpnAdapter::new(
        [
            OpenVpnProfile::new(51, first),
            OpenVpnProfile::new(51, second),
        ],
        RecordingOpenVpnCommandControl::default(),
    );

    assert_eq!(
        adapter.connect(51),
        Err(PrivilegeBrokerError::ActionNotApproved)
    );
    assert!(adapter.command_control().starts.is_empty());
    assert!(adapter.command_control().stops.is_empty());
}

#[test]
fn unknown_openvpn_profile_is_denied_before_executor_trust_is_considered() {
    let config = PathBuf::from("/etc/focus/openvpn/study.ovpn");
    let profile = OpenVpnProfile::new(51, config);
    let command = RecordingOpenVpnCommandControl {
        trusted_executor: false,
        ..RecordingOpenVpnCommandControl::default()
    };
    let mut adapter = OpenVpnAdapter::new([profile], command);

    assert_eq!(
        adapter.connect(99),
        Err(PrivilegeBrokerError::ActionNotApproved)
    );
    assert!(adapter.command_control().starts.is_empty());
    assert!(adapter.command_control().stops.is_empty());
}

#[test]
fn untrusted_openvpn_executor_is_denied_before_service_start() {
    let config = PathBuf::from("/etc/focus/openvpn/study.ovpn");
    let profile = OpenVpnProfile::new(51, config);
    let command = RecordingOpenVpnCommandControl {
        trusted_executor: false,
        ..RecordingOpenVpnCommandControl::default()
    };
    let mut adapter = OpenVpnAdapter::new([profile], command);

    assert_eq!(
        adapter.connect(51),
        Err(PrivilegeBrokerError::UnsafeExecutor)
    );
    assert!(adapter.command_control().starts.is_empty());
    assert!(adapter.command_control().stops.is_empty());
}

#[test]
fn untrusted_openvpn_config_is_denied_before_service_start() {
    let config = PathBuf::from("/etc/focus/openvpn/study.ovpn");
    let profile = OpenVpnProfile::new(51, config);
    let command = RecordingOpenVpnCommandControl {
        trusted_config: false,
        ..RecordingOpenVpnCommandControl::default()
    };
    let mut adapter = OpenVpnAdapter::new([profile], command);

    assert_eq!(
        adapter.connect(51),
        Err(PrivilegeBrokerError::ActionNotApproved)
    );
    assert!(adapter.command_control().starts.is_empty());
    assert!(adapter.command_control().stops.is_empty());
}
