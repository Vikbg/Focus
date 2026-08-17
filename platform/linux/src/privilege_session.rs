#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::reject_existing_privileged_sessions_at;

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
            let process = self.root.join(pid.to_string());
            fs::create_dir(&process).unwrap();
            fs::write(
                process.join("status"),
                format!("Name:\tfixture\nUid:\t{real_uid}\t{effective_uid}\t{effective_uid}\t{effective_uid}\n"),
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
}
