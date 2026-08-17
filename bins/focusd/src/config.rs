use std::{
    env,
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use focus_linux::LinuxBackend;

const DEFAULT_CLI_PATH: &str = "/usr/bin/focusctl";

/// Error returned when the daemon deployment identity is not explicit and valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigError {
    MissingAllowedUid,
    InvalidAllowedUid,
}

impl fmt::Display for RuntimeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAllowedUid => formatter.write_str("FOCUS_ALLOWED_UID must be configured"),
            Self::InvalidAllowedUid => {
                formatter.write_str("FOCUS_ALLOWED_UID must be a valid numeric uid")
            }
        }
    }
}

impl Error for RuntimeConfigError {}

/// Deployment identity used by the privileged daemon to authenticate the CLI peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    allowed_uid: u32,
    cli_executable: PathBuf,
}

impl RuntimeConfig {
    /// Builds runtime identity from explicit configuration values.
    ///
    /// # Errors
    ///
    /// Returns an error when the deployment UID is absent or invalid.
    pub fn from_values(
        allowed_uid: Option<&str>,
        cli_executable: Option<&str>,
    ) -> Result<Self, RuntimeConfigError> {
        let allowed_uid = allowed_uid.ok_or(RuntimeConfigError::MissingAllowedUid)?;
        let allowed_uid = allowed_uid
            .parse::<u32>()
            .map_err(|_| RuntimeConfigError::InvalidAllowedUid)?;
        let cli_executable = PathBuf::from(cli_executable.unwrap_or(DEFAULT_CLI_PATH));
        Ok(Self {
            allowed_uid,
            cli_executable,
        })
    }

    /// Loads the deployment identity from process environment variables.
    ///
    /// # Errors
    ///
    /// Returns an error when `FOCUS_ALLOWED_UID` is absent, non-Unicode, or invalid.
    pub fn from_env() -> Result<Self, RuntimeConfigError> {
        let allowed_uid = env::var("FOCUS_ALLOWED_UID").ok();
        let cli_executable = env::var("FOCUS_CLI_PATH").ok();
        Self::from_values(allowed_uid.as_deref(), cli_executable.as_deref())
    }

    /// Builds the production Linux backend for the configured protected UID.
    #[must_use]
    pub fn linux_backend(&self) -> LinuxBackend {
        LinuxBackend::for_uid(self.allowed_uid)
    }

    #[must_use]
    pub const fn allowed_uid(&self) -> u32 {
        self.allowed_uid
    }

    #[must_use]
    pub fn cli_executable(&self) -> &Path {
        &self.cli_executable
    }
}
