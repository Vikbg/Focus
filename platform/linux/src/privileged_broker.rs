use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use focus_platform::PrivilegedAction;

const SYSTEMCTL_CANDIDATES: [&str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];
const DOCKER_SERVICE: &str = "docker.service";
const DOCKER_STOP_UNITS: [&str; 2] = ["docker.socket", DOCKER_SERVICE];
const WRITEABLE_BY_NON_OWNER: u32 = 0o022;

/// Error returned by the Linux typed privilege broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeBrokerError {
    UnsafeExecutor,
    ActionNotApproved,
    ActionFailed,
}

/// Typed privilege-action control owned by the Linux backend.
pub trait PrivilegeBrokerControl {
    /// Executes one approved typed action.
    ///
    /// # Errors
    ///
    /// Returns an error when the action is not approved, the trusted executor cannot be
    /// established, or the action fails.
    fn execute(&mut self, action: PrivilegedAction) -> Result<(), PrivilegeBrokerError>;
}

/// Fail-closed broker used whenever typed privileged actions are not explicitly wired.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FailClosedPrivilegeBroker;

impl PrivilegeBrokerControl for FailClosedPrivilegeBroker {
    fn execute(&mut self, _action: PrivilegedAction) -> Result<(), PrivilegeBrokerError> {
        Err(PrivilegeBrokerError::UnsafeExecutor)
    }
}

/// Narrow Docker service-control dependency used by the typed broker.
pub trait DockerServiceControl {
    /// Returns whether the fixed production executor is trusted for privileged use.
    ///
    /// # Errors
    ///
    /// Returns an error when executor trust cannot be determined safely.
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError>;

    /// Starts the fixed Docker service.
    ///
    /// This operation is not approved by the Task 21 broker because starting a rootful Docker
    /// daemon can expose a root-equivalent control socket. It remains a narrow dependency for the
    /// Task 22 broker review.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixed service action fails.
    fn start_docker(&mut self) -> Result<(), PrivilegeBrokerError>;

    /// Stops every fixed Docker activation unit.
    ///
    /// # Errors
    ///
    /// Returns an error when any fixed service or socket action fails.
    fn stop_docker(&mut self) -> Result<(), PrivilegeBrokerError>;
}

/// Narrow provider-neutral VPN dependency used by the typed broker.
pub trait VpnActionControl {
    /// Connects one exact VPN identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the identity is not approved or the provider action fails.
    fn connect_vpn(&mut self, id: u128) -> Result<(), PrivilegeBrokerError>;

    /// Disconnects one exact VPN identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the identity is not approved or the provider action fails.
    fn disconnect_vpn(&mut self, id: u128) -> Result<(), PrivilegeBrokerError>;
}

/// VPN control used until a provider-neutral manager is injected by the later VPN phase.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FailClosedVpnActionControl;

impl VpnActionControl for FailClosedVpnActionControl {
    fn connect_vpn(&mut self, _id: u128) -> Result<(), PrivilegeBrokerError> {
        Err(PrivilegeBrokerError::ActionNotApproved)
    }

    fn disconnect_vpn(&mut self, _id: u128) -> Result<(), PrivilegeBrokerError> {
        Err(PrivilegeBrokerError::ActionNotApproved)
    }
}

/// Linux broker that maps closed privileged actions to narrow typed controls.
#[derive(Debug)]
pub struct LinuxPrivilegeBroker<D, V = FailClosedVpnActionControl> {
    control: D,
    vpn_control: V,
}

impl<D> LinuxPrivilegeBroker<D, FailClosedVpnActionControl> {
    /// Creates a broker with Docker control and fail-closed VPN actions.
    #[must_use]
    pub const fn new(control: D) -> Self {
        Self {
            control,
            vpn_control: FailClosedVpnActionControl,
        }
    }
}

impl<D, V> LinuxPrivilegeBroker<D, V> {
    /// Creates a broker from explicit narrow Docker and VPN controls.
    #[must_use]
    pub const fn with_controls(control: D, vpn_control: V) -> Self {
        Self {
            control,
            vpn_control,
        }
    }

    /// Returns the Docker control for deterministic tests and diagnostics.
    #[must_use]
    pub const fn control(&self) -> &D {
        &self.control
    }

    /// Returns the VPN control for deterministic tests and diagnostics.
    #[must_use]
    pub const fn vpn_control(&self) -> &V {
        &self.vpn_control
    }
}

impl<D: Default, V: Default> Default for LinuxPrivilegeBroker<D, V> {
    fn default() -> Self {
        Self::with_controls(D::default(), V::default())
    }
}

impl<D: DockerServiceControl, V: VpnActionControl> PrivilegeBrokerControl
    for LinuxPrivilegeBroker<D, V>
{
    fn execute(&mut self, action: PrivilegedAction) -> Result<(), PrivilegeBrokerError> {
        match action {
            PrivilegedAction::VpnConnect { id } => self.vpn_control.connect_vpn(id),
            PrivilegedAction::VpnDisconnect { id } => self.vpn_control.disconnect_vpn(id),
            PrivilegedAction::DockerStop => {
                if !self.control.executor_is_trusted()? {
                    return Err(PrivilegeBrokerError::UnsafeExecutor);
                }
                self.control.stop_docker()
            }
            PrivilegedAction::DockerStart => Err(PrivilegeBrokerError::ActionNotApproved),
        }
    }
}

/// Production Docker control using only a fixed systemctl path and fixed unit names.
#[derive(Debug, Clone)]
pub struct SystemctlDockerServiceControl {
    executable: Option<PathBuf>,
}

impl Default for SystemctlDockerServiceControl {
    fn default() -> Self {
        Self {
            executable: SYSTEMCTL_CANDIDATES
                .iter()
                .map(PathBuf::from)
                .find(|path| path.exists()),
        }
    }
}

impl SystemctlDockerServiceControl {
    fn trusted_executor_metadata(is_file: bool, owner_uid: u32, mode: u32) -> bool {
        is_file && owner_uid == 0 && mode & 0o111 != 0 && mode & WRITEABLE_BY_NON_OWNER == 0
    }

    fn trusted_path(path: &Path) -> Result<bool, PrivilegeBrokerError> {
        let canonical = fs::canonicalize(path).map_err(|_| PrivilegeBrokerError::UnsafeExecutor)?;
        let metadata = fs::metadata(canonical).map_err(|_| PrivilegeBrokerError::UnsafeExecutor)?;
        Ok(Self::trusted_executor_metadata(
            metadata.is_file(),
            metadata.uid(),
            metadata.permissions().mode() & 0o777,
        ))
    }

    fn run_unit_action(&self, action: &str, unit: &str) -> Result<(), PrivilegeBrokerError> {
        let Some(executable) = self.executable.as_deref() else {
            return Err(PrivilegeBrokerError::UnsafeExecutor);
        };
        if !Self::trusted_path(executable)? {
            return Err(PrivilegeBrokerError::UnsafeExecutor);
        }
        let status = Command::new(executable)
            .args([action, unit])
            .status()
            .map_err(|_| PrivilegeBrokerError::ActionFailed)?;
        if status.success() {
            Ok(())
        } else {
            Err(PrivilegeBrokerError::ActionFailed)
        }
    }
}

impl DockerServiceControl for SystemctlDockerServiceControl {
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError> {
        let Some(executable) = self.executable.as_deref() else {
            return Ok(false);
        };
        Self::trusted_path(executable)
    }

    fn start_docker(&mut self) -> Result<(), PrivilegeBrokerError> {
        self.run_unit_action("start", DOCKER_SERVICE)
    }

    fn stop_docker(&mut self) -> Result<(), PrivilegeBrokerError> {
        for unit in DOCKER_STOP_UNITS {
            self.run_unit_action("stop", unit)?;
        }
        Ok(())
    }
}

/// Production typed privilege broker.
pub type ProductionPrivilegeBroker =
    LinuxPrivilegeBroker<SystemctlDockerServiceControl, FailClosedVpnActionControl>;

#[cfg(test)]
mod tests {
    use super::{DOCKER_STOP_UNITS, SystemctlDockerServiceControl};

    #[test]
    fn docker_stop_disables_socket_activation_before_the_service() {
        assert_eq!(DOCKER_STOP_UNITS, ["docker.socket", "docker.service"]);
    }

    #[test]
    fn trusted_executor_requires_root_owned_non_writable_executable_file() {
        assert!(SystemctlDockerServiceControl::trusted_executor_metadata(
            true, 0, 0o755
        ));
        assert!(!SystemctlDockerServiceControl::trusted_executor_metadata(
            true, 1000, 0o755
        ));
        assert!(!SystemctlDockerServiceControl::trusted_executor_metadata(
            true, 0, 0o775
        ));
        assert!(!SystemctlDockerServiceControl::trusted_executor_metadata(
            true, 0, 0o644
        ));
        assert!(!SystemctlDockerServiceControl::trusted_executor_metadata(
            false, 0, 0o755
        ));
    }
}
