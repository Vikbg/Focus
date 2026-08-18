use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use focus_platform::PrivilegedAction;

const SYSTEMCTL_CANDIDATES: [&str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];
const DOCKER_SERVICE: &str = "docker.service";
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

    /// Stops the fixed Docker service.
    ///
    /// # Errors
    ///
    /// Returns an error when the fixed service action fails.
    fn stop_docker(&mut self) -> Result<(), PrivilegeBrokerError>;
}

/// Linux broker that maps closed privileged actions to narrow service controls.
#[derive(Debug)]
pub struct LinuxPrivilegeBroker<C> {
    control: C,
}

impl<C> LinuxPrivilegeBroker<C> {
    /// Creates a broker from one narrow Docker service-control dependency.
    #[must_use]
    pub const fn new(control: C) -> Self {
        Self { control }
    }

    /// Returns the Docker control for deterministic tests and diagnostics.
    #[must_use]
    pub const fn control(&self) -> &C {
        &self.control
    }
}

impl<C: Default> Default for LinuxPrivilegeBroker<C> {
    fn default() -> Self {
        Self::new(C::default())
    }
}

impl<C: DockerServiceControl> PrivilegeBrokerControl for LinuxPrivilegeBroker<C> {
    fn execute(&mut self, action: PrivilegedAction) -> Result<(), PrivilegeBrokerError> {
        if action == PrivilegedAction::DockerStart {
            return Err(PrivilegeBrokerError::ActionNotApproved);
        }
        if !self.control.executor_is_trusted()? {
            return Err(PrivilegeBrokerError::UnsafeExecutor);
        }

        match action {
            PrivilegedAction::DockerStart => Err(PrivilegeBrokerError::ActionNotApproved),
            PrivilegedAction::DockerStop => self.control.stop_docker(),
        }
    }
}

/// Production Docker control using only a fixed systemctl path and service name.
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

    fn run_service_action(&self, action: &str) -> Result<(), PrivilegeBrokerError> {
        let Some(executable) = self.executable.as_deref() else {
            return Err(PrivilegeBrokerError::UnsafeExecutor);
        };
        if !Self::trusted_path(executable)? {
            return Err(PrivilegeBrokerError::UnsafeExecutor);
        }
        let status = Command::new(executable)
            .args([action, DOCKER_SERVICE])
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
        self.run_service_action("start")
    }

    fn stop_docker(&mut self) -> Result<(), PrivilegeBrokerError> {
        self.run_service_action("stop")
    }
}

/// Production typed privilege broker.
pub type ProductionPrivilegeBroker = LinuxPrivilegeBroker<SystemctlDockerServiceControl>;

#[cfg(test)]
mod tests {
    use super::SystemctlDockerServiceControl;

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
