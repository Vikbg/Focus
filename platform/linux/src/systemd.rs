use std::{fs, io, path::Path};

const SYSTEMD_RUNTIME_PATH: &str = "/run/systemd/system";
const SYSTEMD_USERS_PATH: &str = "/run/systemd/users";

pub(crate) fn is_running() -> bool {
    Path::new(SYSTEMD_RUNTIME_PATH).is_dir()
}

pub(crate) fn active_non_root_user_count() -> io::Result<usize> {
    let entries = match fs::read_dir(SYSTEMD_USERS_PATH) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };

    let mut active_users = 0_usize;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Ok(uid) = name.parse::<u32>() else {
            continue;
        };
        if uid != 0 {
            active_users += 1;
        }
    }
    Ok(active_users)
}
