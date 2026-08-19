use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{PrivilegeBrokerError, VpnActionControl};

const FOCUS_CONFIG_ROOT: &str = "/etc/focus";
const FOCUS_WIREGUARD_CONFIG_ROOT: &str = "/etc/focus/wireguard";
const WG_QUICK_CANDIDATES: [&str; 2] = ["/usr/bin/wg-quick", "/usr/sbin/wg-quick"];
const WRITEABLE_BY_NON_OWNER: u32 = 0o022;
const CONFIG_VISIBLE_TO_NON_OWNER: u32 = 0o077;

/// One pre-approved `WireGuard` profile bound to a stable Focus VPN id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardProfile {
    id: u128,
    config: PathBuf,
}

impl WireGuardProfile {
    /// Creates one pre-approved profile registration.
    #[must_use]
    pub fn new(id: u128, config: PathBuf) -> Self {
        Self { id, config }
    }
}

/// Narrow command dependency used by the `WireGuard` VPN adapter.
pub trait WireGuardCommandControl {
    /// Returns whether the fixed `WireGuard` executor is trusted.
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

    /// Brings up one trusted registered `WireGuard` configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the `WireGuard` command fails.
    fn bring_up(&mut self, config: &Path) -> Result<(), PrivilegeBrokerError>;

    /// Brings down one trusted registered `WireGuard` configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the `WireGuard` command fails.
    fn bring_down(&mut self, config: &Path) -> Result<(), PrivilegeBrokerError>;
}

/// Provider-specific `WireGuard` implementation of the provider-neutral VPN action contract.
#[derive(Debug)]
pub struct WireGuardVpnActionControl<C> {
    profiles: Vec<WireGuardProfile>,
    command_control: C,
}

impl<C> WireGuardVpnActionControl<C> {
    /// Creates the adapter from pre-approved profiles and one narrow command control.
    #[must_use]
    pub fn new<I>(profiles: I, command_control: C) -> Self
    where
        I: IntoIterator<Item = WireGuardProfile>,
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
        self.profiles
            .iter()
            .find(|profile| profile.id == id)
            .map(|profile| profile.config.clone())
    }
}

impl<C: WireGuardCommandControl> VpnActionControl for WireGuardVpnActionControl<C> {
    fn connect_vpn(&mut self, id: u128) -> Result<(), PrivilegeBrokerError> {
        let config = self
            .config_for_id(id)
            .ok_or(PrivilegeBrokerError::ActionNotApproved)?;
        if !self.command_control.executor_is_trusted()? {
            return Err(PrivilegeBrokerError::UnsafeExecutor);
        }
        if !self.command_control.config_is_trusted(&config)? {
            return Err(PrivilegeBrokerError::ActionNotApproved);
        }
        self.command_control.bring_up(&config)
    }

    fn disconnect_vpn(&mut self, id: u128) -> Result<(), PrivilegeBrokerError> {
        let config = self
            .config_for_id(id)
            .ok_or(PrivilegeBrokerError::ActionNotApproved)?;
        if !self.command_control.executor_is_trusted()? {
            return Err(PrivilegeBrokerError::UnsafeExecutor);
        }
        if !self.command_control.config_is_trusted(&config)? {
            return Err(PrivilegeBrokerError::ActionNotApproved);
        }
        self.command_control.bring_down(&config)
    }
}

/// Production boundary for a fixed `wg-quick` executable and Focus-owned configuration scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemWireGuardCommandControl {
    executable: Option<PathBuf>,
}

impl Default for SystemWireGuardCommandControl {
    fn default() -> Self {
        Self {
            executable: WG_QUICK_CANDIDATES
                .iter()
                .map(PathBuf::from)
                .find(|candidate| candidate.exists()),
        }
    }
}

impl SystemWireGuardCommandControl {
    fn trusted_executor_metadata(is_file: bool, owner_uid: u32, mode: u32) -> bool {
        is_file && owner_uid == 0 && mode & 0o111 != 0 && mode & WRITEABLE_BY_NON_OWNER == 0
    }

    fn trusted_config_root_metadata(
        is_directory: bool,
        is_symlink: bool,
        owner_uid: u32,
        mode: u32,
    ) -> bool {
        is_directory && !is_symlink && owner_uid == 0 && mode & WRITEABLE_BY_NON_OWNER == 0
    }

    fn trusted_config_metadata(is_file: bool, is_symlink: bool, owner_uid: u32, mode: u32) -> bool {
        is_file
            && !is_symlink
            && owner_uid == 0
            && mode & CONFIG_VISIBLE_TO_NON_OWNER == 0
            && mode & 0o400 != 0
    }

    fn config_path_is_in_scope(path: &Path) -> bool {
        path.parent() == Some(Path::new(FOCUS_WIREGUARD_CONFIG_ROOT))
            && path.extension().and_then(|extension| extension.to_str()) == Some("conf")
    }

    fn safe_config_contents(contents: &str) -> bool {
        contents.lines().all(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
                return true;
            }
            let Some((key, _value)) = trimmed.split_once('=') else {
                return true;
            };
            !matches!(
                key.trim().to_ascii_lowercase().as_str(),
                "preup" | "postup" | "predown" | "postdown" | "saveconfig"
            )
        })
    }

    fn trusted_executor_path(path: &Path) -> Result<bool, PrivilegeBrokerError> {
        let canonical = fs::canonicalize(path).map_err(|_| PrivilegeBrokerError::UnsafeExecutor)?;
        let metadata = fs::metadata(canonical).map_err(|_| PrivilegeBrokerError::UnsafeExecutor)?;
        Ok(Self::trusted_executor_metadata(
            metadata.is_file(),
            metadata.uid(),
            metadata.permissions().mode() & 0o777,
        ))
    }

    fn trusted_config_root(path: &Path) -> Result<bool, PrivilegeBrokerError> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| PrivilegeBrokerError::ActionNotApproved)?;
        Ok(Self::trusted_config_root_metadata(
            metadata.is_dir(),
            metadata.file_type().is_symlink(),
            metadata.uid(),
            metadata.permissions().mode() & 0o777,
        ))
    }

    fn config_roots_are_trusted() -> Result<bool, PrivilegeBrokerError> {
        for root in [FOCUS_CONFIG_ROOT, FOCUS_WIREGUARD_CONFIG_ROOT] {
            if !Self::trusted_config_root(Path::new(root))? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn run_action(&self, action: &str, config: &Path) -> Result<(), PrivilegeBrokerError> {
        if !self.executor_is_trusted()? {
            return Err(PrivilegeBrokerError::UnsafeExecutor);
        }
        if !self.config_is_trusted(config)? {
            return Err(PrivilegeBrokerError::ActionNotApproved);
        }
        let executable = self
            .executable
            .as_deref()
            .ok_or(PrivilegeBrokerError::UnsafeExecutor)?;
        let status = Command::new(executable)
            .arg(action)
            .arg(config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| PrivilegeBrokerError::ActionFailed)?;
        if status.success() {
            Ok(())
        } else {
            Err(PrivilegeBrokerError::ActionFailed)
        }
    }
}

impl WireGuardCommandControl for SystemWireGuardCommandControl {
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError> {
        let Some(executable) = self.executable.as_deref() else {
            return Ok(false);
        };
        Self::trusted_executor_path(executable)
    }

    fn config_is_trusted(&self, config: &Path) -> Result<bool, PrivilegeBrokerError> {
        if !Self::config_path_is_in_scope(config) || !Self::config_roots_are_trusted()? {
            return Ok(false);
        }

        let metadata =
            fs::symlink_metadata(config).map_err(|_| PrivilegeBrokerError::ActionNotApproved)?;
        if !Self::trusted_config_metadata(
            metadata.is_file(),
            metadata.file_type().is_symlink(),
            metadata.uid(),
            metadata.permissions().mode() & 0o777,
        ) {
            return Ok(false);
        }

        let contents =
            fs::read_to_string(config).map_err(|_| PrivilegeBrokerError::ActionNotApproved)?;
        Ok(Self::safe_config_contents(&contents))
    }

    fn bring_up(&mut self, config: &Path) -> Result<(), PrivilegeBrokerError> {
        self.run_action("up", config)
    }

    fn bring_down(&mut self, config: &Path) -> Result<(), PrivilegeBrokerError> {
        self.run_action("down", config)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::SystemWireGuardCommandControl;

    #[test]
    fn trusted_wg_quick_executor_requires_root_owned_non_writable_executable_file() {
        assert!(SystemWireGuardCommandControl::trusted_executor_metadata(
            true, 0, 0o755
        ));
        assert!(!SystemWireGuardCommandControl::trusted_executor_metadata(
            true, 1000, 0o755
        ));
        assert!(!SystemWireGuardCommandControl::trusted_executor_metadata(
            true, 0, 0o775
        ));
        assert!(!SystemWireGuardCommandControl::trusted_executor_metadata(
            true, 0, 0o644
        ));
        assert!(!SystemWireGuardCommandControl::trusted_executor_metadata(
            false, 0, 0o755
        ));
    }

    #[test]
    fn trusted_wireguard_config_root_is_root_owned_directory_and_not_a_symlink() {
        assert!(SystemWireGuardCommandControl::trusted_config_root_metadata(
            true, false, 0, 0o755
        ));
        assert!(SystemWireGuardCommandControl::trusted_config_root_metadata(
            true, false, 0, 0o700
        ));
        assert!(!SystemWireGuardCommandControl::trusted_config_root_metadata(true, true, 0, 0o755));
        assert!(
            !SystemWireGuardCommandControl::trusted_config_root_metadata(true, false, 1000, 0o755)
        );
        assert!(
            !SystemWireGuardCommandControl::trusted_config_root_metadata(true, false, 0, 0o775)
        );
        assert!(
            !SystemWireGuardCommandControl::trusted_config_root_metadata(false, false, 0, 0o755)
        );
    }

    #[test]
    fn trusted_wireguard_config_is_root_owned_private_regular_and_not_a_symlink() {
        assert!(SystemWireGuardCommandControl::trusted_config_metadata(
            true, false, 0, 0o600
        ));
        assert!(SystemWireGuardCommandControl::trusted_config_metadata(
            true, false, 0, 0o400
        ));
        assert!(!SystemWireGuardCommandControl::trusted_config_metadata(
            true, true, 0, 0o600
        ));
        assert!(!SystemWireGuardCommandControl::trusted_config_metadata(
            true, false, 1000, 0o600
        ));
        assert!(!SystemWireGuardCommandControl::trusted_config_metadata(
            true, false, 0, 0o640
        ));
        assert!(!SystemWireGuardCommandControl::trusted_config_metadata(
            false, false, 0, 0o600
        ));
    }

    #[test]
    fn wireguard_config_scope_is_fixed_and_shell_hooks_are_rejected() {
        assert!(SystemWireGuardCommandControl::config_path_is_in_scope(
            Path::new("/etc/focus/wireguard/study.conf")
        ));
        assert!(!SystemWireGuardCommandControl::config_path_is_in_scope(
            Path::new("/tmp/study.conf")
        ));
        assert!(!SystemWireGuardCommandControl::config_path_is_in_scope(
            Path::new("/etc/focus/wireguard/nested/study.conf")
        ));
        assert!(!SystemWireGuardCommandControl::config_path_is_in_scope(
            Path::new("/etc/focus/wireguard/study.txt")
        ));

        assert!(SystemWireGuardCommandControl::safe_config_contents(
            "[Interface]\nPrivateKey = fixture\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = fixture\nAllowedIPs = 0.0.0.0/0\n"
        ));
        for unsafe_config in [
            "[Interface]\nPostUp = /bin/sh -c whoami\n",
            "[Interface]\n preup = touch /root/bypass\n",
            "[Interface]\nPreDown=/bin/false\n",
            "[Interface]\nPOSTDOWN = /bin/true\n",
            "[Interface]\nSaveConfig = true\n",
        ] {
            assert!(!SystemWireGuardCommandControl::safe_config_contents(
                unsafe_config
            ));
        }
    }
}
