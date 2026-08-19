use crate::PrivilegeBrokerError;

/// Provider-neutral VPN mechanism contract used by Linux adapters.
pub trait VpnAdapter {
    /// Connects one pre-approved VPN profile by stable Focus id.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile is unknown, unsafe, or cannot be connected.
    fn connect(&mut self, id: u128) -> Result<(), PrivilegeBrokerError>;

    /// Disconnects one pre-approved VPN profile by stable Focus id.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile is unknown, unsafe, or cannot be disconnected.
    fn disconnect(&mut self, id: u128) -> Result<(), PrivilegeBrokerError>;
}
