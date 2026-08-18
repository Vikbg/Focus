use std::{fs, io, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrivilegeSessionError {
    InspectionFailed,
    ExistingPrivilegedSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessPrivilegeState {
    real_uid: u32,
    privileged: bool,
}

fn read_process_file(process: &Path, name: &str) -> Result<Option<String>, PrivilegeSessionError> {
    match fs::read_to_string(process.join(name)) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match fs::symlink_metadata(process) {
                Err(process_error) if process_error.kind() == io::ErrorKind::NotFound => Ok(None),
                Ok(_) | Err(_) => Err(PrivilegeSessionError::InspectionFailed),
            }
        }
        Err(_) => Err(PrivilegeSessionError::InspectionFailed),
    }
}

fn status_value<'a>(status: &'a str, label: &str) -> Result<&'a str, PrivilegeSessionError> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(label))
        .ok_or(PrivilegeSessionError::InspectionFailed)
}

fn id_quartet(status: &str, label: &str) -> Result<[u32; 4], PrivilegeSessionError> {
    let mut fields = status_value(status, label)?.split_whitespace();
    let mut ids = [0_u32; 4];
    for id in &mut ids {
        *id = fields
            .next()
            .ok_or(PrivilegeSessionError::InspectionFailed)?
            .parse()
            .map_err(|_| PrivilegeSessionError::InspectionFailed)?;
    }
    if fields.next().is_some() {
        return Err(PrivilegeSessionError::InspectionFailed);
    }
    Ok(ids)
}

fn has_root_supplementary_group(status: &str) -> Result<bool, PrivilegeSessionError> {
    status_value(status, "Groups:")?
        .split_whitespace()
        .try_fold(false, |has_root, field| {
            let group = field
                .parse::<u32>()
                .map_err(|_| PrivilegeSessionError::InspectionFailed)?;
            Ok(has_root || group == 0)
        })
}

fn capability_set(status: &str, label: &str) -> Result<u64, PrivilegeSessionError> {
    let value = status_value(status, label)?.trim();
    if value.is_empty() || value.split_whitespace().count() != 1 {
        return Err(PrivilegeSessionError::InspectionFailed);
    }
    u64::from_str_radix(value, 16).map_err(|_| PrivilegeSessionError::InspectionFailed)
}

fn process_privilege_state(status: &str) -> Result<ProcessPrivilegeState, PrivilegeSessionError> {
    let uids = id_quartet(status, "Uid:")?;
    let gids = id_quartet(status, "Gid:")?;
    let root_group = has_root_supplementary_group(status)?;
    let cap_permitted = capability_set(status, "CapPrm:")?;
    let cap_effective = capability_set(status, "CapEff:")?;
    let cap_ambient = capability_set(status, "CapAmb:")?;

    Ok(ProcessPrivilegeState {
        real_uid: uids[0],
        privileged: uids.contains(&0)
            || gids.contains(&0)
            || root_group
            || cap_permitted != 0
            || cap_effective != 0
            || cap_ambient != 0,
    })
}

pub(crate) fn reject_existing_privileged_sessions_at(
    proc_root: &Path,
    protected_uid: u32,
) -> Result<(), PrivilegeSessionError> {
    let entries = fs::read_dir(proc_root).map_err(|_| PrivilegeSessionError::InspectionFailed)?;

    for entry in entries {
        let entry = entry.map_err(|_| PrivilegeSessionError::InspectionFailed)?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let process = proc_root.join(pid.to_string());
        let Some(status) = read_process_file(&process, "status")? else {
            continue;
        };
        let privilege = process_privilege_state(&status)?;
        if !privilege.privileged {
            continue;
        }
        if privilege.real_uid == protected_uid {
            return Err(PrivilegeSessionError::ExistingPrivilegedSession);
        }

        let Some(login_uid) = read_process_file(&process, "loginuid")? else {
            continue;
        };
        let login_uid = login_uid
            .trim()
            .parse::<u32>()
            .map_err(|_| PrivilegeSessionError::InspectionFailed)?;
        if login_uid == protected_uid {
            return Err(PrivilegeSessionError::ExistingPrivilegedSession);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::reject_existing_privileged_sessions_at;
    use crate::privilege_guard::arm_with_session_scan_at;

    const PAM_RULE: &str = "account requisite pam_listfile.so item=user sense=deny file=/var/lib/focus/privilege-deny-users onerr=fail";

    struct ProcFixture {
        root: PathBuf,
    }

    impl ProcFixture {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after Unix epoch")
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "focus-privilege-session-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            Self { root }
        }

        fn add_process(&self, pid: u32, real_uid: u32, effective_uid: u32, login_uid: u32) {
            self.add_process_status(
                pid,
                [real_uid, effective_uid, effective_uid, effective_uid],
                [real_uid, real_uid, real_uid, real_uid],
                &[real_uid],
                0,
                0,
                0,
                login_uid,
            );
        }

        #[allow(clippy::too_many_arguments)]
        fn add_process_status(
            &self,
            pid: u32,
            uids: [u32; 4],
            gids: [u32; 4],
            groups: &[u32],
            cap_permitted: u64,
            cap_effective: u64,
            cap_ambient: u64,
            login_uid: u32,
        ) {
            let process = self.root.join(pid.to_string());
            fs::create_dir(&process).unwrap();
            let groups = groups
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            fs::write(
                process.join("status"),
                format!(
                    "Name:\tfixture\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nGroups:\t{groups}\nCapPrm:\t{cap_permitted:016x}\nCapEff:\t{cap_effective:016x}\nCapAmb:\t{cap_ambient:016x}\n",
                    uids[0],
                    uids[1],
                    uids[2],
                    uids[3],
                    gids[0],
                    gids[1],
                    gids[2],
                    gids[3],
                ),
            )
            .unwrap();
            fs::write(process.join("loginuid"), format!("{login_uid}\n")).unwrap();
        }
    }

    impl Drop for ProcFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn protected_users_existing_root_process_is_rejected() {
        let fixture = ProcFixture::new();
        fixture.add_process(101, 0, 0, 1000);

        assert!(reject_existing_privileged_sessions_at(&fixture.root, 1000).is_err());
    }

    #[test]
    fn protected_users_setuid_root_process_is_rejected_when_login_uid_is_unset() {
        let fixture = ProcFixture::new();
        fixture.add_process(106, 1000, 0, u32::MAX);

        assert!(reject_existing_privileged_sessions_at(&fixture.root, 1000).is_err());
    }

    #[test]
    fn protected_users_saved_or_fs_root_uid_is_rejected() {
        for (pid, uids) in [
            (107, [1000, 1000, 0, 1000]),
            (108, [1000, 1000, 1000, 0]),
        ] {
            let fixture = ProcFixture::new();
            fixture.add_process_status(
                pid,
                uids,
                [1000; 4],
                &[1000],
                0,
                0,
                0,
                u32::MAX,
            );

            assert!(reject_existing_privileged_sessions_at(&fixture.root, 1000).is_err());
        }
    }

    #[test]
    fn protected_users_root_group_privilege_is_rejected() {
        for (pid, gids, groups) in [
            (109, [1000, 0, 1000, 1000], vec![1000]),
            (110, [1000; 4], vec![1000, 0]),
        ] {
            let fixture = ProcFixture::new();
            fixture.add_process_status(
                pid,
                [1000; 4],
                gids,
                &groups,
                0,
                0,
                0,
                u32::MAX,
            );

            assert!(reject_existing_privileged_sessions_at(&fixture.root, 1000).is_err());
        }
    }

    #[test]
    fn protected_users_permitted_or_effective_capability_is_rejected() {
        for (pid, cap_permitted, cap_effective, cap_ambient) in [
            (111, 1, 0, 0),
            (112, 1, 1, 0),
            (113, 1, 1, 1),
        ] {
            let fixture = ProcFixture::new();
            fixture.add_process_status(
                pid,
                [1000; 4],
                [1000; 4],
                &[1000],
                cap_permitted,
                cap_effective,
                cap_ambient,
                u32::MAX,
            );

            assert!(reject_existing_privileged_sessions_at(&fixture.root, 1000).is_err());
        }
    }

    #[test]
    fn unrelated_system_root_process_is_not_attributed_to_protected_user() {
        let fixture = ProcFixture::new();
        fixture.add_process(102, 0, 0, u32::MAX);
        fixture.add_process(103, 0, 0, 2000);

        assert_eq!(
            reject_existing_privileged_sessions_at(&fixture.root, 1000),
            Ok(())
        );
    }

    #[test]
    fn protected_users_normal_unprivileged_process_is_allowed() {
        let fixture = ProcFixture::new();
        fixture.add_process(104, 1000, 1000, 1000);

        assert_eq!(
            reject_existing_privileged_sessions_at(&fixture.root, 1000),
            Ok(())
        );
    }

    #[test]
    fn privilege_arm_rejects_existing_root_session_before_deny_list_mutation() {
        let proc_fixture = ProcFixture::new();
        proc_fixture.add_process(105, 0, 0, 1000);

        let guard_root = proc_fixture.root.join("guard");
        let state_dir = guard_root.join("state");
        fs::create_dir_all(&state_dir).unwrap();
        fs::set_permissions(&guard_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let pam_config = guard_root.join("sudo");
        fs::write(&pam_config, format!("#%PAM-1.0\n{PAM_RULE}\n")).unwrap();
        fs::set_permissions(&pam_config, fs::Permissions::from_mode(0o644)).unwrap();

        let deny_list = state_dir.join("privilege-deny-users");
        fs::write(&deny_list, "").unwrap();
        fs::set_permissions(&deny_list, fs::Permissions::from_mode(0o600)).unwrap();
        let owner_uid = fs::metadata(&guard_root).unwrap().uid();

        assert!(
            arm_with_session_scan_at(
                &proc_fixture.root,
                &pam_config,
                &deny_list,
                owner_uid,
                "focus-user",
                1000,
            )
            .is_err()
        );
        assert_eq!(fs::read_to_string(deny_list).unwrap(), "");
    }
}
