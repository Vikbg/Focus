use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use focus_core::{ExecutionOrigin, ObservedExecutable};

use crate::{
    ExecutableIdentityError, ExecutionContextClassifier, ExecutionContextError,
    LinuxExecutionFacts, enrich_execution_context, observe_executable,
};

const PROC_ROOT: &str = "/proc";

/// Read-only Linux process facts required to classify one execution.
pub trait LinuxExecutionFactSource {
    /// Returns the executable path for one process.
    ///
    /// # Errors
    ///
    /// Returns an error when the executable path cannot be read safely.
    fn executable_path(&self, pid: u32) -> io::Result<PathBuf>;

    /// Returns the raw NUL-delimited Linux command line.
    ///
    /// # Errors
    ///
    /// Returns an error when the command line cannot be read safely.
    fn cmdline_bytes(&self, pid: u32) -> io::Result<Vec<u8>>;

    /// Returns the raw cgroup membership text.
    ///
    /// # Errors
    ///
    /// Returns an error when cgroup membership cannot be read safely.
    fn cgroup_text(&self, pid: u32) -> io::Result<String>;

    /// Returns the raw process status text.
    ///
    /// # Errors
    ///
    /// Returns an error when process status cannot be read safely.
    fn status_text(&self, pid: u32) -> io::Result<String>;

    /// Returns Flatpak namespace metadata when it exists inside the process root.
    ///
    /// # Errors
    ///
    /// Returns an error when metadata exists but cannot be read safely.
    fn flatpak_info(&self, pid: u32) -> io::Result<Option<String>>;

    /// Returns the kernel security label for the process when available.
    ///
    /// # Errors
    ///
    /// Returns an error when the label exists but cannot be read safely.
    fn security_label(&self, pid: u32) -> io::Result<Option<String>>;
}

/// Production Linux process-fact source backed by procfs.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcfsExecutionFactSource;

impl LinuxExecutionFactSource for ProcfsExecutionFactSource {
    fn executable_path(&self, pid: u32) -> io::Result<PathBuf> {
        Ok(proc_path(pid, "exe"))
    }

    fn cmdline_bytes(&self, pid: u32) -> io::Result<Vec<u8>> {
        fs::read(proc_path(pid, "cmdline"))
    }

    fn cgroup_text(&self, pid: u32) -> io::Result<String> {
        fs::read_to_string(proc_path(pid, "cgroup"))
    }

    fn status_text(&self, pid: u32) -> io::Result<String> {
        fs::read_to_string(proc_path(pid, "status"))
    }

    fn flatpak_info(&self, pid: u32) -> io::Result<Option<String>> {
        read_optional_text(proc_path(pid, "root/.flatpak-info"))
    }

    fn security_label(&self, pid: u32) -> io::Result<Option<String>> {
        read_optional_text(proc_path(pid, "attr/current"))
    }
}

/// Error returned while collecting and classifying Linux process execution facts.
#[derive(Debug)]
pub enum ExecutionFactCollectionError {
    Source {
        field: &'static str,
        source: io::Error,
    },
    InvalidCmdline,
    MissingUnifiedCgroup,
    InvalidParentPid,
    InvalidFlatpakInfo,
    Executable(ExecutableIdentityError),
    Context(ExecutionContextError),
}

impl fmt::Display for ExecutionFactCollectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source { field, source } => {
                write!(
                    formatter,
                    "Linux execution fact read failed for {field}: {source}"
                )
            }
            Self::InvalidCmdline => formatter.write_str("invalid Linux process command line"),
            Self::MissingUnifiedCgroup => {
                formatter.write_str("Linux process is missing unified cgroup v2 membership")
            }
            Self::InvalidParentPid => formatter.write_str("invalid Linux parent process id"),
            Self::InvalidFlatpakInfo => formatter.write_str("invalid Flatpak application metadata"),
            Self::Executable(error) => write!(formatter, "invalid executable identity: {error}"),
            Self::Context(error) => write!(formatter, "invalid execution context: {error}"),
        }
    }
}

impl Error for ExecutionFactCollectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Source { source, .. } => Some(source),
            Self::Executable(error) => Some(error),
            Self::Context(error) => Some(error),
            Self::InvalidCmdline
            | Self::MissingUnifiedCgroup
            | Self::InvalidParentPid
            | Self::InvalidFlatpakInfo => None,
        }
    }
}

/// Collects and classifies one Linux process observation from verified OS facts.
///
/// Package-looking strings in process arguments are never treated as package identity. Flatpak
/// identity comes only from `.flatpak-info` visible inside the process root. Snap identity comes
/// only from a kernel security label in enforce mode.
///
/// # Errors
///
/// Returns an error when required procfs facts cannot be read or parsed, the executable or parent
/// identity cannot be observed safely, or verified execution facts conflict.
pub fn collect_execution_observation<S: LinuxExecutionFactSource>(
    source: &S,
    pid: u32,
    classifier: &ExecutionContextClassifier,
) -> Result<ObservedExecutable, ExecutionFactCollectionError> {
    let executable_path = source
        .executable_path(pid)
        .map_err(|source| source_error("executable", source))?;
    let executable = observe_executable(executable_path, ExecutionOrigin::Direct)
        .map_err(ExecutionFactCollectionError::Executable)?;

    let cmdline = source
        .cmdline_bytes(pid)
        .map_err(|source| source_error("cmdline", source))?;
    let argv = parse_cmdline(&cmdline)?;

    let cgroup = source
        .cgroup_text(pid)
        .map_err(|source| source_error("cgroup", source))?;
    let unified_cgroup = parse_unified_cgroup(&cgroup)?;

    let status = source
        .status_text(pid)
        .map_err(|source| source_error("status", source))?;
    let parent_pid = parse_parent_pid(&status)?;

    let mut facts = LinuxExecutionFacts::new(argv).with_cgroup(unified_cgroup);

    if parent_pid != 0 {
        let parent_path = source
            .executable_path(parent_pid)
            .map_err(|source| source_error("parent executable", source))?;
        let parent = observe_executable(parent_path, ExecutionOrigin::Direct)
            .map_err(ExecutionFactCollectionError::Executable)?;
        facts = facts.with_parent(parent);
    }

    if let Some(info) = source
        .flatpak_info(pid)
        .map_err(|source| source_error("flatpak metadata", source))?
    {
        let app_id = parse_flatpak_app_id(&info)?;
        facts = facts.with_verified_flatpak_app_id(app_id);
    }

    if let Some(label) = source
        .security_label(pid)
        .map_err(|source| source_error("security label", source))?
        && let Some(package_id) = parse_snap_enforced_package(&label)
    {
        facts = facts.with_verified_snap_package_id(package_id);
    }

    enrich_execution_context(executable, &facts, classifier)
        .map_err(ExecutionFactCollectionError::Context)
}

fn source_error(field: &'static str, source: io::Error) -> ExecutionFactCollectionError {
    ExecutionFactCollectionError::Source { field, source }
}

fn proc_path(pid: u32, suffix: &str) -> PathBuf {
    Path::new(PROC_ROOT).join(pid.to_string()).join(suffix)
}

fn read_optional_text(path: PathBuf) -> io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn parse_cmdline(bytes: &[u8]) -> Result<Vec<String>, ExecutionFactCollectionError> {
    if bytes.is_empty() {
        return Err(ExecutionFactCollectionError::InvalidCmdline);
    }

    let mut fields: Vec<&[u8]> = bytes.split(|byte| *byte == 0).collect();
    if fields.last().is_some_and(|field| field.is_empty()) {
        fields.pop();
    }
    if fields.is_empty() || fields[0].is_empty() {
        return Err(ExecutionFactCollectionError::InvalidCmdline);
    }

    fields
        .into_iter()
        .map(|field| {
            std::str::from_utf8(field)
                .map(str::to_owned)
                .map_err(|_| ExecutionFactCollectionError::InvalidCmdline)
        })
        .collect()
}

fn parse_unified_cgroup(text: &str) -> Result<String, ExecutionFactCollectionError> {
    let path = text.lines().find_map(|line| line.strip_prefix("0::"));
    match path {
        Some(path) if path.starts_with('/') && !path.contains('\0') => Ok(path.to_owned()),
        _ => Err(ExecutionFactCollectionError::MissingUnifiedCgroup),
    }
}

fn parse_parent_pid(status: &str) -> Result<u32, ExecutionFactCollectionError> {
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .map(str::trim)
        .ok_or(ExecutionFactCollectionError::InvalidParentPid)?;
    value
        .parse::<u32>()
        .map_err(|_| ExecutionFactCollectionError::InvalidParentPid)
}

fn parse_flatpak_app_id(info: &str) -> Result<String, ExecutionFactCollectionError> {
    let mut in_application = false;
    let mut application_name: Option<String> = None;

    for raw_line in info.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_application = line == "[Application]";
            continue;
        }
        if !in_application {
            continue;
        }
        let Some(value) = line.strip_prefix("name=") else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() || application_name.is_some() || !valid_package_id(value) {
            return Err(ExecutionFactCollectionError::InvalidFlatpakInfo);
        }
        application_name = Some(value.to_owned());
    }

    application_name.ok_or(ExecutionFactCollectionError::InvalidFlatpakInfo)
}

fn parse_snap_enforced_package(label: &str) -> Option<String> {
    let label = label.trim();
    let profile = label.strip_suffix(" (enforce)")?;
    let remainder = profile.strip_prefix("snap.")?;
    let (package, app) = remainder.split_once('.')?;
    if package.is_empty() || app.is_empty() || !valid_snap_name(package) || !valid_snap_name(app) {
        return None;
    }
    Some(package.to_owned())
}

fn valid_package_id(value: &str) -> bool {
    value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_snap_name(value: &str) -> bool {
    value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
