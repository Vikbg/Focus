use std::path::{Path, PathBuf};

use crate::{PrivilegeBrokerError, VpnActionControl, VpnAdapter};

const FOCUS_OPENVPN_CONFIG_ROOT: &str = "/etc/focus/openvpn";
const OPENVPN_CANDIDATES: [&str; 2] = ["/usr/sbin/openvpn", "/usr/bin/openvpn"];
const SYSTEMD_RUN_CANDIDATES: [&str; 2] = ["/usr/bin/systemd-run", "/bin/systemd-run"];
const SYSTEMCTL_CANDIDATES: [&str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];

/// One pre-approved `OpenVPN` profile bound to a stable Focus VPN id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVpnProfile {
    id: u128,
    config: PathBuf,
}

impl OpenVpnProfile {
    /// Creates one pre-approved `OpenVPN` profile registration.
    #[must_use]
    pub fn new(id: u128, config: PathBuf) -> Self {
        Self { id, config }
    }
}

/// Narrow command dependency used by the `OpenVPN` adapter.
pub trait OpenVpnCommandControl {
    /// Returns whether the fixed production executor is trusted.
    ///
    /// # Errors
    ///
    /// Returns an error when executor trust cannot be established safely.
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError>;

    /// Returns whether one registered configuration remains trusted.
    ///
    /// # Errors
    ///
    /// Returns an error when configuration trust cannot be established safely.
    fn config_is_trusted(&self, config: &Path) -> Result<bool, PrivilegeBrokerError>;

    /// Starts one approved `OpenVPN` profile under a deterministic Focus-owned systemd unit.
    ///
    /// # Errors
    ///
    /// Returns an error when the service cannot be started.
    fn start_service(&mut self, unit: &str, config: &Path) -> Result<(), PrivilegeBrokerError>;

    /// Stops one deterministic Focus-owned `OpenVPN` systemd unit.
    ///
    /// # Errors
    ///
    /// Returns an error when the service cannot be stopped.
    fn stop_service(&mut self, unit: &str) -> Result<(), PrivilegeBrokerError>;
}

/// Provider-specific `OpenVPN` implementation of the provider-neutral VPN contract.
#[derive(Debug)]
pub struct OpenVpnAdapter<C> {
    profiles: Vec<OpenVpnProfile>,
    command_control: C,
}

impl<C> OpenVpnAdapter<C> {
    /// Creates the adapter from pre-approved profiles and one narrow command control.
    #[must_use]
    pub fn new<I>(profiles: I, command_control: C) -> Self
    where
        I: IntoIterator<Item = OpenVpnProfile>,
    {
        Self {
            profiles: profiles.into_iter().collect(),
            command_control,
        }
    }

    /// Returns the command dependency for deterministic tests and diagnostics.
    #[must_use]
    pub const fn command_control(&self) -> &C {
        &self.command_control
    }

    fn config_for_id(&self, id: u128) -> Option<PathBuf> {
        let mut matches = self.profiles.iter().filter(|profile| profile.id == id);
        let profile = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(profile.config.clone())
    }

    fn unit_for_id(id: u128) -> String {
        format!("focus-openvpn-{id}.service")
    }
}

impl<C: OpenVpnCommandControl> VpnAdapter for OpenVpnAdapter<C> {
    fn connect(&mut self, id: u128) -> Result<(), PrivilegeBrokerError> {
        let config = self
            .config_for_id(id)
            .ok_or(PrivilegeBrokerError::ActionNotApproved)?;
        if !self.command_control.executor_is_trusted()? {
            return Err(PrivilegeBrokerError::UnsafeExecutor);
        }
        if !self.command_control.config_is_trusted(&config)? {
            return Err(PrivilegeBrokerError::ActionNotApproved);
        }
        self.command_control
            .start_service(&Self::unit_for_id(id), &config)
    }

    fn disconnect(&mut self, id: u128) -> Result<(), PrivilegeBrokerError> {
        self.config_for_id(id)
            .ok_or(PrivilegeBrokerError::ActionNotApproved)?;
        self.command_control.stop_service(&Self::unit_for_id(id))
    }
}

impl<C: OpenVpnCommandControl> VpnActionControl for OpenVpnAdapter<C> {
    fn connect_vpn(&mut self, id: u128) -> Result<(), PrivilegeBrokerError> {
        VpnAdapter::connect(self, id)
    }

    fn disconnect_vpn(&mut self, id: u128) -> Result<(), PrivilegeBrokerError> {
        VpnAdapter::disconnect(self, id)
    }
}

/// Production boundary for fixed `OpenVPN`, systemd-run, and systemctl executors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemOpenVpnCommandControl {
    openvpn: Option<PathBuf>,
    systemd_run: Option<PathBuf>,
    systemctl: Option<PathBuf>,
}

impl Default for SystemOpenVpnCommandControl {
    fn default() -> Self {
        Self {
            openvpn: OPENVPN_CANDIDATES
                .iter()
                .map(PathBuf::from)
                .find(|candidate| candidate.exists()),
            systemd_run: SYSTEMD_RUN_CANDIDATES
                .iter()
                .map(PathBuf::from)
                .find(|candidate| candidate.exists()),
            systemctl: SYSTEMCTL_CANDIDATES
                .iter()
                .map(PathBuf::from)
                .find(|candidate| candidate.exists()),
        }
    }
}

impl OpenVpnCommandControl for SystemOpenVpnCommandControl {
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError> {
        let _all_executors_present =
            self.openvpn.is_some() && self.systemd_run.is_some() && self.systemctl.is_some();
        Ok(false)
    }

    fn config_is_trusted(&self, config: &Path) -> Result<bool, PrivilegeBrokerError> {
        let _in_fixed_scope = config.parent() == Some(Path::new(FOCUS_OPENVPN_CONFIG_ROOT));
        Ok(false)
    }

    fn start_service(&mut self, _unit: &str, _config: &Path) -> Result<(), PrivilegeBrokerError> {
        Err(PrivilegeBrokerError::ActionNotApproved)
    }

    fn stop_service(&mut self, _unit: &str) -> Result<(), PrivilegeBrokerError> {
        Err(PrivilegeBrokerError::ActionNotApproved)
    }
}

#[cfg(test)]
mod tests {
    use super::SystemOpenVpnCommandControl;

    #[test]
    fn trusted_openvpn_executor_requires_root_owned_non_writable_executable_file() {
        assert!(SystemOpenVpnCommandControl::trusted_executor_metadata(
            true, 0, 0o755
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_executor_metadata(
            true, 1000, 0o755
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_executor_metadata(
            true, 0, 0o775
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_executor_metadata(
            true, 0, 0o644
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_executor_metadata(
            false, 0, 0o755
        ));
    }
}
