use std::{
    error::Error,
    fmt, fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
};

use crate::systemd;

const CGROUP_V2_CONTROLLERS: &str = "/sys/fs/cgroup/cgroup.controllers";
const FANOTIFY_LIMIT: &str = "/proc/sys/fs/fanotify/max_queued_events";
const PROC_SELF_STATUS: &str = "/proc/self/status";
const FOCUS_RUNTIME_DIR: &str = "/run/focus";
const RUNTIME_PARENT: &str = "/run";

/// Health of one Linux preflight capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Healthy,
    Unavailable,
    Degraded,
}

/// Complete Linux readiness report used before strict-session enforcement starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxPreflightReport {
    pub systemd: Health,
    pub cgroup_v2: Health,
    pub fanotify: Health,
    pub nftables: Health,
    pub filesystem_permissions: Health,
    pub privilege_model: Health,
    pub multi_user_state: Health,
    pub active_users: usize,
}

impl LinuxPreflightReport {
    /// Returns true only when every capability required for a strict session is healthy.
    #[must_use]
    pub const fn is_strict_ready(&self) -> bool {
        matches!(self.systemd, Health::Healthy)
            && matches!(self.cgroup_v2, Health::Healthy)
            && matches!(self.fanotify, Health::Healthy)
            && matches!(self.nftables, Health::Healthy)
            && matches!(self.filesystem_permissions, Health::Healthy)
            && matches!(self.privilege_model, Health::Healthy)
            && matches!(self.multi_user_state, Health::Healthy)
    }

    fn degraded_capabilities(&self) -> Vec<&'static str> {
        let mut degraded = Vec::new();
        if self.systemd != Health::Healthy {
            degraded.push("systemd");
        }
        if self.cgroup_v2 != Health::Healthy {
            degraded.push("cgroup_v2");
        }
        if self.fanotify != Health::Healthy {
            degraded.push("fanotify");
        }
        if self.nftables != Health::Healthy {
            degraded.push("nftables");
        }
        if self.filesystem_permissions != Health::Healthy {
            degraded.push("filesystem_permissions");
        }
        if self.privilege_model != Health::Healthy {
            degraded.push("privilege_model");
        }
        if self.multi_user_state != Health::Healthy {
            degraded.push("multi_user_state");
        }
        degraded
    }
}

/// Error returned by Linux preflight probing or strict readiness evaluation.
#[derive(Debug)]
pub enum LinuxError {
    Probe {
        capability: &'static str,
        source: io::Error,
    },
    InvalidProcessStatus,
    StrictPreflightFailed {
        degraded: Vec<&'static str>,
    },
}

impl fmt::Display for LinuxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Probe { capability, source } => {
                write!(
                    formatter,
                    "Linux preflight probe failed for {capability}: {source}"
                )
            }
            Self::InvalidProcessStatus => {
                formatter.write_str("Linux preflight could not parse effective UID")
            }
            Self::StrictPreflightFailed { degraded } => {
                write!(
                    formatter,
                    "strict Linux preflight failed: {}",
                    degraded.join(", ")
                )
            }
        }
    }
}

impl Error for LinuxError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Probe { source, .. } => Some(source),
            Self::InvalidProcessStatus | Self::StrictPreflightFailed { .. } => None,
        }
    }
}

/// Read-only Linux system probes used to build a deterministic preflight report.
pub trait SystemProbe {
    /// Reports whether systemd is the active system manager.
    ///
    /// # Errors
    ///
    /// Returns an error when the probe cannot determine the state safely.
    fn systemd_available(&self) -> Result<bool, LinuxError>;

    /// Reports whether the unified cgroup v2 hierarchy is available.
    ///
    /// # Errors
    ///
    /// Returns an error when the probe cannot determine the state safely.
    fn cgroup_v2_available(&self) -> Result<bool, LinuxError>;

    /// Reports whether the kernel exposes fanotify support required by Focus.
    ///
    /// # Errors
    ///
    /// Returns an error when the probe cannot determine the state safely.
    fn fanotify_available(&self) -> Result<bool, LinuxError>;

    /// Reports whether the nftables userspace command is available.
    ///
    /// # Errors
    ///
    /// Returns an error when command discovery fails unexpectedly.
    fn nftables_available(&self) -> Result<bool, LinuxError>;

    /// Reports whether the protected runtime path can be created with the expected ownership model.
    ///
    /// # Errors
    ///
    /// Returns an error when filesystem metadata cannot be inspected safely.
    fn filesystem_permissions_ready(&self) -> Result<bool, LinuxError>;

    /// Reports whether the daemon currently has the privilege level required by strict Linux guards.
    ///
    /// # Errors
    ///
    /// Returns an error when process identity cannot be read or parsed.
    fn privilege_model_ready(&self) -> Result<bool, LinuxError>;

    /// Returns the number of non-root systemd user managers currently present.
    ///
    /// # Errors
    ///
    /// Returns an error when the systemd runtime directory cannot be inspected safely.
    fn active_user_count(&self) -> Result<usize, LinuxError>;
}

/// Read-only probe implementation for the current Linux host.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostSystemProbe;

impl SystemProbe for HostSystemProbe {
    fn systemd_available(&self) -> Result<bool, LinuxError> {
        Ok(systemd::is_running())
    }

    fn cgroup_v2_available(&self) -> Result<bool, LinuxError> {
        Ok(Path::new(CGROUP_V2_CONTROLLERS).is_file())
    }

    fn fanotify_available(&self) -> Result<bool, LinuxError> {
        Ok(Path::new(FANOTIFY_LIMIT).is_file())
    }

    fn nftables_available(&self) -> Result<bool, LinuxError> {
        match Command::new("nft")
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) => Ok(status.success()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(LinuxError::Probe {
                capability: "nftables",
                source,
            }),
        }
    }

    fn filesystem_permissions_ready(&self) -> Result<bool, LinuxError> {
        let path = if Path::new(FOCUS_RUNTIME_DIR).exists() {
            Path::new(FOCUS_RUNTIME_DIR)
        } else {
            Path::new(RUNTIME_PARENT)
        };
        let metadata = fs::symlink_metadata(path).map_err(|source| LinuxError::Probe {
            capability: "filesystem_permissions",
            source,
        })?;
        let mode = metadata.permissions().mode();
        let secure_type = metadata.file_type().is_dir() && !metadata.file_type().is_symlink();
        let root_owned = metadata.uid() == 0;
        let owner_writable = mode & 0o200 != 0;
        let unsafe_world_write = mode & 0o002 != 0;
        Ok(secure_type && root_owned && owner_writable && !unsafe_world_write)
    }

    fn privilege_model_ready(&self) -> Result<bool, LinuxError> {
        let status = fs::read_to_string(PROC_SELF_STATUS).map_err(|source| LinuxError::Probe {
            capability: "privilege_model",
            source,
        })?;
        let uid_line = status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .ok_or(LinuxError::InvalidProcessStatus)?;
        let effective_uid = uid_line
            .split_whitespace()
            .nth(2)
            .ok_or(LinuxError::InvalidProcessStatus)?
            .parse::<u32>()
            .map_err(|_| LinuxError::InvalidProcessStatus)?;
        Ok(effective_uid == 0)
    }

    fn active_user_count(&self) -> Result<usize, LinuxError> {
        systemd::active_non_root_user_count().map_err(|source| LinuxError::Probe {
            capability: "multi_user_state",
            source,
        })
    }
}

const fn health(available: bool) -> Health {
    if available {
        Health::Healthy
    } else {
        Health::Unavailable
    }
}

/// Evaluates Linux strict-session readiness using a supplied read-only probe.
///
/// # Errors
///
/// Returns an error when any underlying probe cannot determine its capability safely.
pub fn evaluate_preflight<P: SystemProbe>(probe: &P) -> Result<LinuxPreflightReport, LinuxError> {
    let active_users = probe.active_user_count()?;
    Ok(LinuxPreflightReport {
        systemd: health(probe.systemd_available()?),
        cgroup_v2: health(probe.cgroup_v2_available()?),
        fanotify: health(probe.fanotify_available()?),
        nftables: health(probe.nftables_available()?),
        filesystem_permissions: health(probe.filesystem_permissions_ready()?),
        privilege_model: health(probe.privilege_model_ready()?),
        multi_user_state: if active_users <= 1 {
            Health::Healthy
        } else {
            Health::Degraded
        },
        active_users,
    })
}

/// Rejects a Linux preflight report when any required strict-session capability is degraded.
///
/// # Errors
///
/// Returns [`LinuxError::StrictPreflightFailed`] with every degraded capability.
pub fn require_strict_preflight(report: &LinuxPreflightReport) -> Result<(), LinuxError> {
    if report.is_strict_ready() {
        return Ok(());
    }
    Err(LinuxError::StrictPreflightFailed {
        degraded: report.degraded_capabilities(),
    })
}

/// Samples the current Linux host and returns its strict-session readiness report.
///
/// The probe is read-only and does not install or arm privileged enforcement components.
///
/// # Errors
///
/// Returns an error when a host capability cannot be inspected safely.
pub async fn preflight() -> Result<LinuxPreflightReport, LinuxError> {
    evaluate_preflight(&HostSystemProbe)
}
