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
}
