const PRIVILEGE_DENY_LIST_PATH: &str = "/var/lib/focus/privilege-deny-users";
const REQUIRED_PAM_ACCOUNT_RULE: &str = "account requisite pam_listfile.so item=user sense=deny file=/var/lib/focus/privilege-deny-users onerr=fail";

/// Error returned by the Linux privilege-restriction guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeGuardError {
    Unavailable,
    Unhealthy,
    DisarmFailed,
}

/// Typed privilege-restriction control owned by the Linux backend.
pub trait PrivilegeGuardControl {
    /// Arms the privilege restriction for the protected user.
    ///
    /// # Errors
    ///
    /// Returns an error until the required PAM policy and deny-list can be applied safely.
    fn arm(&mut self) -> Result<(), PrivilegeGuardError>;

    /// Verifies that the privilege restriction remains active and healthy.
    ///
    /// # Errors
    ///
    /// Returns an error while no verified production restriction is active.
    fn verify(&mut self) -> Result<(), PrivilegeGuardError>;

    /// Removes the privilege restriction. The operation must be idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error when an active restriction cannot be removed safely.
    fn disarm(&mut self) -> Result<(), PrivilegeGuardError>;
}

/// Production privilege-restriction guard scoped to one protected effective UID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionPrivilegeGuard {
    enforced_uid: u32,
}

impl ProductionPrivilegeGuard {
    /// Creates a privilege guard for one protected effective UID.
    #[must_use]
    pub const fn for_uid(enforced_uid: u32) -> Self {
        Self { enforced_uid }
    }

    /// Returns the protected effective UID.
    #[must_use]
    pub const fn enforced_uid(self) -> u32 {
        self.enforced_uid
    }

    /// Returns the exact fail-closed PAM account rule required by this guard.
    #[must_use]
    pub const fn required_pam_account_rule(self) -> &'static str {
        let _ = self;
        REQUIRED_PAM_ACCOUNT_RULE
    }

    /// Returns the root-owned deny-list path referenced by the PAM account rule.
    #[must_use]
    pub const fn deny_list_path(self) -> &'static str {
        let _ = self;
        PRIVILEGE_DENY_LIST_PATH
    }
}

impl PrivilegeGuardControl for ProductionPrivilegeGuard {
    fn arm(&mut self) -> Result<(), PrivilegeGuardError> {
        Err(PrivilegeGuardError::Unavailable)
    }

    fn verify(&mut self) -> Result<(), PrivilegeGuardError> {
        Err(PrivilegeGuardError::Unhealthy)
    }

    fn disarm(&mut self) -> Result<(), PrivilegeGuardError> {
        Ok(())
    }
}
