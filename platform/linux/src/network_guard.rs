use crate::{
    FocusNftablesControl, FocusNftablesError, FocusNftablesTransaction, SystemNftablesControl,
    reload_focus_nftables, remove_focus_nftables,
};

/// Error returned by strict outbound network-guard operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkGuardError {
    Unavailable,
    Nftables(FocusNftablesError),
}

impl From<FocusNftablesError> for NetworkGuardError {
    fn from(error: FocusNftablesError) -> Self {
        Self::Nftables(error)
    }
}

/// Typed lifecycle contract for the strict outbound network guard.
pub trait NetworkGuardControl {
    /// Applies and verifies the strict Focus-owned outbound baseline.
    ///
    /// # Errors
    ///
    /// Returns an error when the strict baseline cannot be applied or verified.
    fn arm(&mut self) -> Result<(), NetworkGuardError>;

    /// Verifies the strict Focus-owned outbound baseline by read-back.
    ///
    /// # Errors
    ///
    /// Returns an error when the observed Focus-owned state differs from the strict baseline.
    fn verify(&mut self) -> Result<(), NetworkGuardError>;

    /// Removes only Focus-owned network state.
    ///
    /// # Errors
    ///
    /// Returns an error when the Focus-owned nftables table cannot be removed safely.
    fn disarm(&mut self) -> Result<(), NetworkGuardError>;
}

/// Fail-closed network guard used when no production network controller is installed.
#[derive(Debug, Default, Clone, Copy)]
pub struct FailClosedNetworkGuard;

impl NetworkGuardControl for FailClosedNetworkGuard {
    fn arm(&mut self) -> Result<(), NetworkGuardError> {
        Err(NetworkGuardError::Unavailable)
    }

    fn verify(&mut self) -> Result<(), NetworkGuardError> {
        Err(NetworkGuardError::Unavailable)
    }

    fn disarm(&mut self) -> Result<(), NetworkGuardError> {
        Err(NetworkGuardError::Unavailable)
    }
}

/// Production strict outbound network guard backed by Focus-owned nftables state.
#[derive(Debug)]
pub struct ProductionNetworkGuard<C = SystemNftablesControl> {
    control: C,
    transaction: FocusNftablesTransaction,
}

impl Default for ProductionNetworkGuard<SystemNftablesControl> {
    fn default() -> Self {
        Self {
            control: SystemNftablesControl::default(),
            transaction: FocusNftablesTransaction::strict_outbound(),
        }
    }
}

impl<C> ProductionNetworkGuard<C> {
    /// Creates a strict outbound guard with an explicit nftables control dependency.
    #[must_use]
    pub fn with_control(control: C) -> Self {
        Self {
            control,
            transaction: FocusNftablesTransaction::strict_outbound(),
        }
    }
}

impl<C: FocusNftablesControl> NetworkGuardControl for ProductionNetworkGuard<C> {
    fn arm(&mut self) -> Result<(), NetworkGuardError> {
        reload_focus_nftables(&mut self.control, &self.transaction).map_err(NetworkGuardError::from)
    }

    fn verify(&mut self) -> Result<(), NetworkGuardError> {
        self.control
            .verify_focus_table(&self.transaction)
            .map_err(NetworkGuardError::from)
    }

    fn disarm(&mut self) -> Result<(), NetworkGuardError> {
        remove_focus_nftables(&mut self.control).map_err(NetworkGuardError::from)
    }
}
