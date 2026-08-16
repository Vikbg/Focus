use std::{
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use focus_core::{ExecutionOrigin, ObservedExecutable};

use crate::{
    ExecutableIdentityError, ExecutionContextClassifier, ExecutionContextError,
    LinuxExecutionFacts, ProcessLifetime, RunningProcess, enrich_execution_context,
    observe_executable,
};

const PROC_ROOT: &str = "/proc";
const PROC_STAT_STARTTIME_INDEX_AFTER_COMM: usize = 19;

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

    /// Returns the raw process stat text used to bind a PID to one lifetime.
    ///
    /// # Errors
    ///
    /// Returns an error when process stat data cannot be read safely.
    fn stat_text(&self, pid: u32) -> io::Result<String>;

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

    fn stat_text(&self, pid: u32) -> io::Result<String> {
        fs::read_to_string(proc_path(pid, "stat"))
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
    InvalidProcessIdentity,
    ProcessIdentityChanged,
    InvalidFlatpakInfo,
    Executable(ExecutableIdentityError),
    Context(ExecutionContextError),
}

impl ExecutionFactCollectionError {
    /// Returns whether collection failed because the process disappeared from procfs.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        match self {
            Self::Source { source, .. } => source.kind() == io::ErrorKind::NotFound,
            Self::Executable(ExecutableIdentityError::Io(source)) => {
                source.kind() == io::ErrorKind::NotFound
            }
            Self::InvalidCmdline
            | Self::MissingUnifiedCgroup
            | Self::InvalidParentPid
            | Self::InvalidProcessIdentity
            | Self::ProcessIdentityChanged
            | Self::InvalidFlatpakInfo
            | Self::Executable(
                ExecutableIdentityError::NonUtf8Path
                | ExecutableIdentityError::NotRegularFile
                | ExecutableIdentityError::NotExecutable,
            )
            | Self::Context(_) => false,
        }
    }
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
            Self::InvalidProcessIdentity => {
                formatter.write_str("invalid Linux process lifetime identity")
            }
            Self::ProcessIdentityChanged => {
                formatter.write_str("Linux process identity changed during observation")
            }
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
            | Self::InvalidProcessIdentity
            | Self::ProcessIdentityChanged
            | Self::InvalidFlatpakInfo => None,
        }
    }
}

/// Collects one Linux process together with the lifetime verified around all execution facts.
///
/// Package-looking strings in process arguments are never treated as package identity. Flatpak
/// identity comes only from `.flatpak-info` visible inside the process root. Snap identity comes
/// only from a kernel security label in enforce mode. The process and its direct parent are each
/// bound to a stable `(pid, starttime)` lifetime before and after observation so PID reuse cannot
/// combine facts from different processes.
///
/// # Errors
///
/// Returns an error when required procfs facts cannot be read or parsed, the executable or parent
/// identity cannot be observed safely, a process lifetime changes during collection, or verified
/// execution facts conflict.
pub fn collect_running_process<S: LinuxExecutionFactSource>(
    source: &S,
    pid: u32,
    classifier: &ExecutionContextClassifier,
) -> Result<RunningProcess, ExecutionFactCollectionError> {
    let lifetime = read_process_lifetime(source, pid, "stat")?;

    let executable_path = source
        .executable_path(pid)
        .map_err(|source| source_error("executable", source))?;
    let executable = observe_executable(executable_path, ExecutionOrigin::Direct)
        .map_err(ExecutionFactCollectionError::Executable)?;
    let executable = enrich_execution_target_context_with_lifetime(
        source, pid, lifetime, executable, classifier,
    )?;

    Ok(RunningProcess::new(lifetime, executable))
}

/// Enriches an already-observed execution target with stable requester process context.
///
/// The supplied executable identity is preserved. The requester PID is used only for
/// argv, cgroup, verified package, parent, and execution-origin context. The requester
/// lifetime is verified before and after collection so PID reuse cannot mix identities.
///
/// # Errors
///
/// Returns an error when requester facts cannot be read or parsed, the requester or its
/// parent changes lifetime during collection, or verified execution facts conflict.
pub fn enrich_execution_target_context<S: LinuxExecutionFactSource>(
    source: &S,
    pid: u32,
    executable: ObservedExecutable,
    classifier: &ExecutionContextClassifier,
) -> Result<ObservedExecutable, ExecutionFactCollectionError> {
    let lifetime = read_process_lifetime(source, pid, "stat")?;
    enrich_execution_target_context_with_lifetime(source, pid, lifetime, executable, classifier)
}

fn enrich_execution_target_context_with_lifetime<S: LinuxExecutionFactSource>(
    source: &S,
    pid: u32,
    lifetime: ProcessLifetime,
    executable: ObservedExecutable,
    classifier: &ExecutionContextClassifier,
) -> Result<ObservedExecutable, ExecutionFactCollectionError> {
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
        let parent_lifetime = read_process_lifetime(source, parent_pid, "parent stat")?;
        let parent_path = source
            .executable_path(parent_pid)
            .map_err(|source| source_error("parent executable", source))?;
        let parent = observe_executable(parent_path, ExecutionOrigin::Direct)
            .map_err(ExecutionFactCollectionError::Executable)?;
        verify_process_lifetime(source, parent_lifetime, "parent stat")?;
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

    verify_process_lifetime(source, lifetime, "stat")?;
    enrich_execution_context(executable, &facts, classifier)
        .map_err(ExecutionFactCollectionError::Context)
}

/// Collects only the executable observation for callers that do not need the process lifetime.
///
/// # Errors
///
/// Returns the same errors as [`collect_running_process`].
pub fn collect_execution_observation<S: LinuxExecutionFactSource>(
    source: &S,
    pid: u32,
    classifier: &ExecutionContextClassifier,
) -> Result<ObservedExecutable, ExecutionFactCollectionError> {
    collect_running_process(source, pid, classifier).map(|process| process.executable().clone())
}

fn source_error(field: &'static str, source: io::Error) -> ExecutionFactCollectionError {
    ExecutionFactCollectionError::Source { field, source }
}

pub(crate) fn read_process_lifetime<S: LinuxExecutionFactSource>(
    source: &S,
    pid: u32,
    field: &'static str,
) -> Result<ProcessLifetime, ExecutionFactCollectionError> {
    let stat = source
        .stat_text(pid)
        .map_err(|source| source_error(field, source))?;
    let starttime = parse_process_starttime(pid, &stat)?;
    Ok(ProcessLifetime::new(pid, starttime))
}

fn verify_process_lifetime<S: LinuxExecutionFactSource>(
    source: &S,
    expected: ProcessLifetime,
    field: &'static str,
) -> Result<(), ExecutionFactCollectionError> {
    let current = read_process_lifetime(source, expected.pid(), field)?;
    if current == expected {
        Ok(())
    } else {
        Err(ExecutionFactCollectionError::ProcessIdentityChanged)
    }
}

fn parse_process_starttime(
    expected_pid: u32,
    stat: &str,
) -> Result<u64, ExecutionFactCollectionError> {
    let stat = stat.trim_end();
    let open_paren = stat
        .find('(')
        .ok_or(ExecutionFactCollectionError::InvalidProcessIdentity)?;
    let close_paren = stat
        .rfind(')')
        .filter(|close_paren| *close_paren > open_paren)
        .ok_or(ExecutionFactCollectionError::InvalidProcessIdentity)?;

    let pid = stat[..open_paren]
        .trim()
        .parse::<u32>()
        .map_err(|_| ExecutionFactCollectionError::InvalidProcessIdentity)?;
    if pid != expected_pid {
        return Err(ExecutionFactCollectionError::InvalidProcessIdentity);
    }

    let fields = stat[close_paren + 1..]
        .split_whitespace()
        .collect::<Vec<_>>();
    let starttime = fields
        .get(PROC_STAT_STARTTIME_INDEX_AFTER_COMM)
        .ok_or(ExecutionFactCollectionError::InvalidProcessIdentity)?;

    starttime
        .parse::<u64>()
        .map_err(|_| ExecutionFactCollectionError::InvalidProcessIdentity)
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
