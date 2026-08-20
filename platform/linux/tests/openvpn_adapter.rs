use std::path::{Path, PathBuf};

use focus_linux::{
    OpenVpnAdapter, OpenVpnCommandControl, OpenVpnProfile, PrivilegeBrokerError, VpnAdapter,
};

#[derive(Debug, Default)]
struct RecordingOpenVpnCommandControl {
    starts: Vec<(String, PathBuf)>,
    stops: Vec<String>,
}

impl OpenVpnCommandControl for RecordingOpenVpnCommandControl {
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError> {
        Ok(true)
    }

    fn config_is_trusted(&self, _config: &Path) -> Result<bool, PrivilegeBrokerError> {
        Ok(true)
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
