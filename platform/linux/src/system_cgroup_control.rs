use std::{
    fs,
    io::Write,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use crate::{
    FocusCgroupClass, FocusCgroupControl, FocusCgroupError, ProcessLifetime,
    ProcfsExecutionFactSource, execution_fact_collector::read_process_lifetime,
};

/// Fixed production root for Focus-owned cgroup v2 process classes.
pub const FOCUS_CGROUP_ROOT: &str = "/sys/fs/cgroup/focus";

const CGROUP_V2_CONTROLLERS: &str = "/sys/fs/cgroup/cgroup.controllers";
const CGROUP_PROCS: &str = "cgroup.procs";
const WRITEABLE_BY_NON_OWNER: u32 = 0o022;
const CLASSES: [FocusCgroupClass; 5] = [
    FocusCgroupClass::Browser,
    FocusCgroupClass::Development,
    FocusCgroupClass::Vpn,
    FocusCgroupClass::System,
    FocusCgroupClass::Blocked,
];

/// Production cgroup v2 control limited to the fixed Focus-owned class hierarchy.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCgroupControl;

impl SystemCgroupControl {
    /// Returns the immutable Focus-owned production cgroup root.
    #[must_use]
    pub fn root(&self) -> &'static Path {
        Path::new(FOCUS_CGROUP_ROOT)
    }

    /// Returns the fixed production path for one typed Focus cgroup class.
    #[must_use]
    pub fn class_path(&self, class: FocusCgroupClass) -> PathBuf {
        self.root().join(class.as_str())
    }

    fn ensure_cgroup_v2() -> Result<(), FocusCgroupError> {
        let metadata = fs::symlink_metadata(CGROUP_V2_CONTROLLERS)
            .map_err(|_| FocusCgroupError::PreparationFailed)?;
        if metadata.file_type().is_file() && metadata.uid() == 0 {
            Ok(())
        } else {
            Err(FocusCgroupError::PreparationFailed)
        }
    }

    fn ensure_safe_directory(path: &Path) -> Result<(), FocusCgroupError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => Self::validate_directory_metadata(&metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(path).map_err(|_| FocusCgroupError::PreparationFailed)?;
                let metadata =
                    fs::symlink_metadata(path).map_err(|_| FocusCgroupError::PreparationFailed)?;
                Self::validate_directory_metadata(&metadata)
            }
            Err(_) => Err(FocusCgroupError::PreparationFailed),
        }
    }

    fn validate_directory_metadata(metadata: &fs::Metadata) -> Result<(), FocusCgroupError> {
        let mode = metadata.mode() & 0o777;
        if metadata.file_type().is_dir()
            && metadata.uid() == 0
            && mode & WRITEABLE_BY_NON_OWNER == 0
        {
            Ok(())
        } else {
            Err(FocusCgroupError::PreparationFailed)
        }
    }

    fn require_existing_safe_class(
        self,
        class: FocusCgroupClass,
        error: FocusCgroupError,
    ) -> Result<PathBuf, FocusCgroupError> {
        let root_metadata = fs::symlink_metadata(self.root()).map_err(|_| error)?;
        Self::validate_directory_metadata(&root_metadata).map_err(|_| error)?;

        let path = self.class_path(class);
        let metadata = fs::symlink_metadata(&path).map_err(|_| error)?;
        Self::validate_directory_metadata(&metadata).map_err(|_| error)?;
        Ok(path)
    }

    fn revalidate_lifetime(
        expected: ProcessLifetime,
        error: FocusCgroupError,
    ) -> Result<(), FocusCgroupError> {
        let current = read_process_lifetime(
            &ProcfsExecutionFactSource,
            expected.pid(),
            "cgroup process stat",
        )
        .map_err(|_| error)?;
        if current == expected {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn write_process(path: &Path, lifetime: ProcessLifetime) -> Result<(), FocusCgroupError> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(path.join(CGROUP_PROCS))
            .map_err(|_| FocusCgroupError::PlacementFailed)?;
        write!(file, "{}", lifetime.pid()).map_err(|_| FocusCgroupError::PlacementFailed)?;
        file.flush().map_err(|_| FocusCgroupError::PlacementFailed)
    }

    fn class_contains(path: &Path, pid: u32) -> Result<bool, FocusCgroupError> {
        let content = fs::read_to_string(path.join(CGROUP_PROCS))
            .map_err(|_| FocusCgroupError::VerificationFailed)?;
        let mut found = false;
        for line in content.lines() {
            let observed = line
                .parse::<u32>()
                .map_err(|_| FocusCgroupError::VerificationFailed)?;
            found |= observed == pid;
        }
        Ok(found)
    }
}

impl FocusCgroupControl for SystemCgroupControl {
    fn prepare_classes(&mut self) -> Result<(), FocusCgroupError> {
        Self::ensure_cgroup_v2()?;
        Self::ensure_safe_directory(self.root())?;
        for class in CLASSES {
            Self::ensure_safe_directory(&self.class_path(class))?;
        }
        Ok(())
    }

    fn place_process(
        &mut self,
        class: FocusCgroupClass,
        lifetime: ProcessLifetime,
    ) -> Result<(), FocusCgroupError> {
        if lifetime.pid() == 0 {
            return Err(FocusCgroupError::InvalidPid);
        }
        Self::revalidate_lifetime(lifetime, FocusCgroupError::PlacementFailed)?;
        let path = self.require_existing_safe_class(class, FocusCgroupError::PlacementFailed)?;
        Self::write_process(&path, lifetime)?;
        Self::revalidate_lifetime(lifetime, FocusCgroupError::PlacementFailed)
    }

    fn verify_process(
        &mut self,
        class: FocusCgroupClass,
        lifetime: ProcessLifetime,
    ) -> Result<(), FocusCgroupError> {
        if lifetime.pid() == 0 {
            return Err(FocusCgroupError::InvalidPid);
        }
        Self::revalidate_lifetime(lifetime, FocusCgroupError::VerificationFailed)?;
        let path = self.require_existing_safe_class(class, FocusCgroupError::VerificationFailed)?;
        if !Self::class_contains(&path, lifetime.pid())? {
            return Err(FocusCgroupError::VerificationFailed);
        }
        Self::revalidate_lifetime(lifetime, FocusCgroupError::VerificationFailed)
    }
}
