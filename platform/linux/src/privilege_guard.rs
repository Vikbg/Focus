use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use nix::unistd::{Uid, User};

const PAM_CONFIG_PATH: &str = "/etc/pam.d/sudo";
const PRIVILEGE_DENY_LIST_PATH: &str = "/var/lib/focus/privilege-deny-users";
const REQUIRED_PAM_ACCOUNT_RULE: &str = "account requisite pam_listfile.so item=user sense=deny file=/var/lib/focus/privilege-deny-users onerr=fail";
const SAFE_FILE_WRITE_MODE: u32 = 0o600;
const SYSTEM_OWNER_UID: u32 = 0;
const WRITEABLE_BY_NON_OWNER: u32 = 0o022;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Error returned by the Linux privilege-restriction guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeGuardError {
    Unavailable,
    Unhealthy,
    DisarmFailed,
    InvalidUserIdentity,
    UnsafePamConfiguration,
    MissingPamRule,
    UnsafeStateDirectory,
    UnsafeDenyList,
}

/// Typed privilege-restriction control owned by the Linux backend.
pub trait PrivilegeGuardControl {
    /// Arms the privilege restriction for the protected user.
    ///
    /// # Errors
    ///
    /// Returns an error when the protected user cannot be resolved or the required PAM policy and
    /// deny-list cannot be applied safely.
    fn arm(&mut self) -> Result<(), PrivilegeGuardError>;

    /// Verifies that the privilege restriction remains active and healthy.
    ///
    /// # Errors
    ///
    /// Returns an error when the protected user cannot be resolved or the PAM policy and deny-list
    /// no longer match the armed restriction.
    fn verify(&mut self) -> Result<(), PrivilegeGuardError>;

    /// Removes the privilege restriction. The operation must be idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error when an active restriction cannot be removed safely.
    fn disarm(&mut self) -> Result<(), PrivilegeGuardError>;
}

#[derive(Debug, Clone, Copy)]
struct PrivilegeGuardPaths<'a> {
    pam_config: &'a Path,
    deny_list: &'a Path,
}

impl<'a> PrivilegeGuardPaths<'a> {
    const fn new(pam_config: &'a Path, deny_list: &'a Path) -> Self {
        Self {
            pam_config,
            deny_list,
        }
    }
}

fn production_paths() -> PrivilegeGuardPaths<'static> {
    PrivilegeGuardPaths::new(
        Path::new(PAM_CONFIG_PATH),
        Path::new(PRIVILEGE_DENY_LIST_PATH),
    )
}

fn safe_identity(identity: &str) -> bool {
    !identity.is_empty()
        && !identity
            .chars()
            .any(|character| matches!(character, '\n' | '\r' | '\0'))
}

fn resolve_username(uid: u32) -> Result<String, PrivilegeGuardError> {
    let user = User::from_uid(Uid::from_raw(uid))
        .map_err(|_| PrivilegeGuardError::Unavailable)?
        .ok_or(PrivilegeGuardError::InvalidUserIdentity)?;
    if !safe_identity(&user.name) {
        return Err(PrivilegeGuardError::InvalidUserIdentity);
    }
    Ok(user.name)
}

fn safe_owned_regular_file(
    path: &Path,
    owner_uid: u32,
    exact_mode: Option<u32>,
) -> io::Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.uid() != owner_uid {
        return Ok(false);
    }
    let mode = metadata.permissions().mode() & 0o777;
    Ok(
        exact_mode.map_or(mode & WRITEABLE_BY_NON_OWNER == 0, |expected| {
            mode == expected
        }),
    )
}

fn safe_owned_directory(path: &Path, owner_uid: u32) -> io::Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(!metadata.file_type().is_symlink()
        && metadata.is_dir()
        && metadata.uid() == owner_uid
        && metadata.permissions().mode() & WRITEABLE_BY_NON_OWNER == 0)
}

fn pam_rule_present(content: &str) -> bool {
    content.lines().any(|line| {
        let trimmed = line.trim();
        !trimmed.starts_with('#')
            && trimmed.split_whitespace().collect::<Vec<_>>().join(" ") == REQUIRED_PAM_ACCOUNT_RULE
    })
}

fn validate_pam_configuration(
    paths: PrivilegeGuardPaths<'_>,
    owner_uid: u32,
) -> Result<(), PrivilegeGuardError> {
    match safe_owned_regular_file(paths.pam_config, owner_uid, None) {
        Ok(true) => {}
        Ok(false) | Err(_) => return Err(PrivilegeGuardError::UnsafePamConfiguration),
    }
    let content =
        fs::read_to_string(paths.pam_config).map_err(|_| PrivilegeGuardError::Unavailable)?;
    if !pam_rule_present(&content) {
        return Err(PrivilegeGuardError::MissingPamRule);
    }
    Ok(())
}

fn validate_state_directory(
    paths: PrivilegeGuardPaths<'_>,
    owner_uid: u32,
) -> Result<&Path, PrivilegeGuardError> {
    let parent = paths
        .deny_list
        .parent()
        .ok_or(PrivilegeGuardError::UnsafeStateDirectory)?;
    match safe_owned_directory(parent, owner_uid) {
        Ok(true) => Ok(parent),
        Ok(false) | Err(_) => Err(PrivilegeGuardError::UnsafeStateDirectory),
    }
}

fn validate_deny_list(
    paths: PrivilegeGuardPaths<'_>,
    owner_uid: u32,
) -> Result<(), PrivilegeGuardError> {
    match safe_owned_regular_file(paths.deny_list, owner_uid, Some(SAFE_FILE_WRITE_MODE)) {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(PrivilegeGuardError::UnsafeDenyList),
    }
}

fn atomic_write_deny_list(
    paths: PrivilegeGuardPaths<'_>,
    owner_uid: u32,
    content: &str,
) -> Result<(), PrivilegeGuardError> {
    let parent = validate_state_directory(paths, owner_uid)?;
    match fs::symlink_metadata(paths.deny_list) {
        Ok(_) => validate_deny_list(paths, owner_uid)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(PrivilegeGuardError::UnsafeDenyList),
    }

    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".privilege-deny-users.tmp.{}.{}",
        std::process::id(),
        sequence
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(SAFE_FILE_WRITE_MODE)
            .open(&temp)
            .map_err(|_| PrivilegeGuardError::Unavailable)?;
        file.write_all(content.as_bytes())
            .map_err(|_| PrivilegeGuardError::Unavailable)?;
        file.sync_all()
            .map_err(|_| PrivilegeGuardError::Unavailable)?;
        if !safe_owned_regular_file(&temp, owner_uid, Some(SAFE_FILE_WRITE_MODE)).unwrap_or(false) {
            return Err(PrivilegeGuardError::UnsafeDenyList);
        }
        fs::rename(&temp, paths.deny_list).map_err(|_| PrivilegeGuardError::Unavailable)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| PrivilegeGuardError::Unavailable)?;
        validate_deny_list(paths, owner_uid)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn arm_at_paths(
    paths: PrivilegeGuardPaths<'_>,
    owner_uid: u32,
    username: &str,
) -> Result<(), PrivilegeGuardError> {
    if !safe_identity(username) {
        return Err(PrivilegeGuardError::InvalidUserIdentity);
    }
    validate_pam_configuration(paths, owner_uid)?;
    atomic_write_deny_list(paths, owner_uid, &format!("{username}\n"))?;
    verify_at_paths(paths, owner_uid, username)
}

fn verify_at_paths(
    paths: PrivilegeGuardPaths<'_>,
    owner_uid: u32,
    username: &str,
) -> Result<(), PrivilegeGuardError> {
    if !safe_identity(username) {
        return Err(PrivilegeGuardError::InvalidUserIdentity);
    }
    validate_pam_configuration(paths, owner_uid)?;
    validate_deny_list(paths, owner_uid)?;
    let content =
        fs::read_to_string(paths.deny_list).map_err(|_| PrivilegeGuardError::Unhealthy)?;
    if content != format!("{username}\n") {
        return Err(PrivilegeGuardError::Unhealthy);
    }
    Ok(())
}

fn disarm_at_paths(
    paths: PrivilegeGuardPaths<'_>,
    owner_uid: u32,
) -> Result<(), PrivilegeGuardError> {
    atomic_write_deny_list(paths, owner_uid, "").map_err(|_| PrivilegeGuardError::DisarmFailed)
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
        let username = resolve_username(self.enforced_uid)?;
        arm_at_paths(production_paths(), SYSTEM_OWNER_UID, &username)
    }

    fn verify(&mut self) -> Result<(), PrivilegeGuardError> {
        let username = resolve_username(self.enforced_uid)?;
        verify_at_paths(production_paths(), SYSTEM_OWNER_UID, &username)
    }

    fn disarm(&mut self) -> Result<(), PrivilegeGuardError> {
        disarm_at_paths(production_paths(), SYSTEM_OWNER_UID)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt, symlink},
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        PrivilegeGuardError, PrivilegeGuardPaths, REQUIRED_PAM_ACCOUNT_RULE, arm_at_paths,
        arm_at_paths_with_session_scan, disarm_at_paths, verify_at_paths,
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
        assert_eq!(
            fs::read_to_string(&fixture.deny_list).unwrap(),
            "focus-user\n"
        );
        verify_at_paths(paths, fixture.owner_uid, "focus-user").unwrap();

        disarm_at_paths(paths, fixture.owner_uid).unwrap();
        disarm_at_paths(paths, fixture.owner_uid).unwrap();
        assert_eq!(fs::read_to_string(&fixture.deny_list).unwrap(), "");
        assert_eq!(
            fs::metadata(&fixture.deny_list)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn existing_privileged_session_fails_arm_after_deny_list_is_applied() {
        let fixture = Fixture::new();
        let proc_root = fixture.root.join("proc");
        let process = proc_root.join("101");
        fs::create_dir_all(&process).unwrap();
        fs::write(
            process.join("status"),
            "Name:\tfixture\nUid:\t0\t0\t0\t0\n",
        )
        .unwrap();
        fs::write(process.join("loginuid"), "1000\n").unwrap();

        assert_eq!(
            arm_at_paths_with_session_scan(
                fixture.paths(),
                fixture.owner_uid,
                "focus-user",
                &proc_root,
                1000,
            ),
            Err(PrivilegeGuardError::ExistingPrivilegedSession)
        );
        assert_eq!(
            fs::read_to_string(&fixture.deny_list).unwrap(),
            "focus-user\n"
        );
    }

    #[test]
    fn pam_symlink_is_rejected_before_deny_list_mutation() {
        let fixture = Fixture::new();
        let target = fixture.root.join("sudo-target");
        fs::rename(&fixture.pam_config, &target).unwrap();
        symlink(&target, &fixture.pam_config).unwrap();

        assert_eq!(
            arm_at_paths(fixture.paths(), fixture.owner_uid, "focus-user"),
            Err(PrivilegeGuardError::UnsafePamConfiguration)
        );
        assert_eq!(fs::read_to_string(&fixture.deny_list).unwrap(), "");
    }

    #[test]
    fn missing_pam_rule_is_rejected_before_deny_list_mutation() {
        let fixture = Fixture::new();
        fs::write(&fixture.pam_config, "#%PAM-1.0\n@include common-auth\n").unwrap();

        assert_eq!(
            arm_at_paths(fixture.paths(), fixture.owner_uid, "focus-user"),
            Err(PrivilegeGuardError::MissingPamRule)
        );
        assert_eq!(fs::read_to_string(&fixture.deny_list).unwrap(), "");
    }

    #[test]
    fn writable_state_directory_is_rejected() {
        let fixture = Fixture::new();
        let state_dir = fixture.deny_list.parent().unwrap();
        fs::set_permissions(state_dir, fs::Permissions::from_mode(0o777)).unwrap();

        assert_eq!(
            arm_at_paths(fixture.paths(), fixture.owner_uid, "focus-user"),
            Err(PrivilegeGuardError::UnsafeStateDirectory)
        );
    }

    #[test]
    fn deny_list_symlink_is_rejected() {
        let fixture = Fixture::new();
        let target = fixture.root.join("deny-target");
        fs::write(&target, "").unwrap();
        fs::remove_file(&fixture.deny_list).unwrap();
        symlink(&target, &fixture.deny_list).unwrap();

        assert_eq!(
            arm_at_paths(fixture.paths(), fixture.owner_uid, "focus-user"),
            Err(PrivilegeGuardError::UnsafeDenyList)
        );
    }

    #[test]
    fn weak_deny_list_mode_is_rejected() {
        let fixture = Fixture::new();
        fs::set_permissions(&fixture.deny_list, fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(
            arm_at_paths(fixture.paths(), fixture.owner_uid, "focus-user"),
            Err(PrivilegeGuardError::UnsafeDenyList)
        );
    }

    #[test]
    fn unsafe_username_is_rejected_before_privilege_files_are_touched() {
        let fixture = Fixture::new();

        assert_eq!(
            arm_at_paths(fixture.paths(), fixture.owner_uid, "focus-user\nroot"),
            Err(PrivilegeGuardError::InvalidUserIdentity)
        );
        assert_eq!(fs::read_to_string(&fixture.deny_list).unwrap(), "");
    }
}
