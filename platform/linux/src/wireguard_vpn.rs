use std::path::{Path, PathBuf};

use crate::{PrivilegeBrokerError, VpnActionControl};

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
