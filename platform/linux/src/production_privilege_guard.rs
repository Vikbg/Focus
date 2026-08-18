use std::{
    fs,
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use nix::unistd::{Uid, User};

use crate::privilege_guard::{
    PrivilegeGuardControl, PrivilegeGuardError,
    ProductionPrivilegeGuard as SudoPrivilegeGuard,
};

const PAM_LOGIN_CONFIG_PATH: &str = "/etc/pam.d/sudo-i";
const SYSTEM_OWNER_UID: u32 = 0;
const WRITEABLE_BY_NON_OWNER: u32 = 0o022;

/// Production privilege guard that validates both sudo PAM service stacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionPrivilegeGuard {
    inner: SudoPrivilegeGuard,
}

impl ProductionPrivilegeGuard {
    /// Creates a privilege guard for one protected effective UID.
    #[must_use]
    pub const fn for_uid(enforced_uid: u32) -> Self {
        Self {
            inner: SudoPrivilegeGuard::for_uid(enforced_uid),
        }
    }

    /// Returns the protected effective UID.
    #[must_use]
    pub const fn enforced_uid(self) -> u32 {
        self.inner.enforced_uid()
    }

    /// Returns the exact fail-closed PAM account rule required by both sudo service stacks.
    #[must_use]
    pub const fn required_pam_account_rule(self) -> &'static str {
        self.inner.required_pam_account_rule()
    }

    /// Returns the root-owned deny-list path referenced by the PAM account rule.
    #[must_use]
    pub const fn deny_list_path(self) -> &'static str {
        self.inner.deny_list_path()
    }
}

impl PrivilegeGuardControl for ProductionPrivilegeGuard {
    fn arm(&mut self) -> Result<(), PrivilegeGuardError> {
        validate_user_identity(self.enforced_uid())?;
        validate_login_pam_configuration(
            Path::new(PAM_LOGIN_CONFIG_PATH),
            SYSTEM_OWNER_UID,
            self.required_pam_account_rule(),
        )?;
        self.inner.arm()
    }

    fn verify(&mut self) -> Result<(), PrivilegeGuardError> {
        validate_user_identity(self.enforced_uid())?;
        validate_login_pam_configuration(
            Path::new(PAM_LOGIN_CONFIG_PATH),
            SYSTEM_OWNER_UID,
            self.required_pam_account_rule(),
        )?;
        self.inner.verify()
    }

    fn disarm(&mut self) -> Result<(), PrivilegeGuardError> {
        self.inner.disarm()
    }
}

fn validate_user_identity(uid: u32) -> Result<(), PrivilegeGuardError> {
    let user = User::from_uid(Uid::from_raw(uid))
        .map_err(|_| PrivilegeGuardError::Unavailable)?
        .ok_or(PrivilegeGuardError::InvalidUserIdentity)?;
    if user.name.is_empty()
        || user
            .name
            .chars()
            .any(|character| matches!(character, '\n' | '\r' | '\0'))
    {
        return Err(PrivilegeGuardError::InvalidUserIdentity);
    }
    Ok(())
}

fn safe_owned_regular_file(path: &Path, owner_uid: u32) -> io::Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.uid() != owner_uid {
        return Ok(false);
    }
    let mode = metadata.permissions().mode() & 0o777;
    Ok(mode & WRITEABLE_BY_NON_OWNER == 0)
}

fn pam_rule_present(content: &str, required_rule: &str) -> bool {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let normalized = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
        if normalized == required_rule {
            return true;
        }
        if normalized.starts_with("account ") || normalized.starts_with("@include ") {
            return false;
        }
    }
    false
}

fn validate_login_pam_configuration(
    path: &Path,
    owner_uid: u32,
    required_rule: &str,
) -> Result<(), PrivilegeGuardError> {
    match safe_owned_regular_file(path, owner_uid) {
        Ok(true) => {}
        Ok(false) | Err(_) => return Err(PrivilegeGuardError::UnsafePamConfiguration),
    }
    let content = fs::read_to_string(path).map_err(|_| PrivilegeGuardError::Unavailable)?;
    if !pam_rule_present(&content, required_rule) {
        return Err(PrivilegeGuardError::MissingPamRule);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::validate_login_pam_configuration;
    use crate::PrivilegeGuardError;

    const RULE: &str = "account requisite pam_listfile.so item=user sense=deny file=/var/lib/focus/privilege-deny-users onerr=fail";

    struct Fixture {
        root: PathBuf,
        pam_login: PathBuf,
        owner_uid: u32,
    }

    impl Fixture {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after Unix epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "focus-production-privilege-guard-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let pam_login = root.join("sudo-i");
            fs::write(
                &pam_login,
                format!("#%PAM-1.0\n{RULE}\n@include sudo\n"),
            )
            .unwrap();
            fs::set_permissions(&pam_login, fs::Permissions::from_mode(0o644)).unwrap();
            let owner_uid = fs::metadata(&root).unwrap().uid();
            Self {
                root,
                pam_login,
                owner_uid,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn sudo_login_stack_requires_the_fail_closed_account_rule_before_include() {
        let fixture = Fixture::new();

        assert_eq!(
            validate_login_pam_configuration(&fixture.pam_login, fixture.owner_uid, RULE),
            Ok(())
        );

        fs::write(&fixture.pam_login, "#%PAM-1.0\n@include sudo\n").unwrap();
        assert_eq!(
            validate_login_pam_configuration(&fixture.pam_login, fixture.owner_uid, RULE),
            Err(PrivilegeGuardError::MissingPamRule)
        );
    }

    #[test]
    fn sudo_login_stack_rejects_rule_after_include() {
        let fixture = Fixture::new();
        fs::write(
            &fixture.pam_login,
            format!("#%PAM-1.0\n@include sudo\n{RULE}\n"),
        )
        .unwrap();

        assert_eq!(
            validate_login_pam_configuration(&fixture.pam_login, fixture.owner_uid, RULE),
            Err(PrivilegeGuardError::MissingPamRule)
        );
    }

    #[test]
    fn sudo_login_stack_rejects_symlink_or_non_owner_writable_configuration() {
        let fixture = Fixture::new();
        fs::set_permissions(&fixture.pam_login, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            validate_login_pam_configuration(&fixture.pam_login, fixture.owner_uid, RULE),
            Err(PrivilegeGuardError::UnsafePamConfiguration)
        );

        let target = fixture.root.join("sudo-i-target");
        fs::write(&target, format!("{RULE}\n")).unwrap();
        fs::remove_file(&fixture.pam_login).unwrap();
        symlink(&target, &fixture.pam_login).unwrap();
        assert_eq!(
            validate_login_pam_configuration(&fixture.pam_login, fixture.owner_uid, RULE),
            Err(PrivilegeGuardError::UnsafePamConfiguration)
        );
    }
}
