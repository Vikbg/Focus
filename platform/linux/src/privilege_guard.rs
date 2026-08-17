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

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        PrivilegeGuardPaths, REQUIRED_PAM_ACCOUNT_RULE, arm_at_paths, disarm_at_paths,
        verify_at_paths,
    };

    struct Fixture {
        root: PathBuf,
        pam_config: PathBuf,
        deny_list: PathBuf,
        owner_uid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after Unix epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "focus-privilege-guard-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let state_dir = root.join("state");
            fs::create_dir(&state_dir).unwrap();
            fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();

            let pam_config = root.join("sudo");
            fs::write(
                &pam_config,
                format!("#%PAM-1.0\n{REQUIRED_PAM_ACCOUNT_RULE}\n@include common-auth\n"),
            )
            .unwrap();
            fs::set_permissions(&pam_config, fs::Permissions::from_mode(0o644)).unwrap();

            let deny_list = state_dir.join("privilege-deny-users");
            fs::write(&deny_list, "").unwrap();
            fs::set_permissions(&deny_list, fs::Permissions::from_mode(0o600)).unwrap();

            let owner_uid = fs::metadata(&root).unwrap().uid();
            Self {
                root,
                pam_config,
                deny_list,
                owner_uid,
            }
        }

        fn paths(&self) -> PrivilegeGuardPaths<'_> {
            PrivilegeGuardPaths::new(&self.pam_config, &self.deny_list)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn safe_privilege_files_arm_verify_and_disarm_idempotently() {
        let fixture = Fixture::new();
        let paths = fixture.paths();

        arm_at_paths(paths, fixture.owner_uid, "focus-user").unwrap();
        assert_eq!(fs::read_to_string(&fixture.deny_list).unwrap(), "focus-user\n");
        verify_at_paths(paths, fixture.owner_uid, "focus-user").unwrap();

        disarm_at_paths(paths, fixture.owner_uid).unwrap();
        disarm_at_paths(paths, fixture.owner_uid).unwrap();
        assert_eq!(fs::read_to_string(&fixture.deny_list).unwrap(), "");
        assert_eq!(
            fs::metadata(&fixture.deny_list).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
