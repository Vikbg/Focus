//! Linux-specific Focus enforcement backend.

mod backend;
mod cgroup_process_class;
mod executable_identity;
mod execution_context;
mod execution_fact_collector;
mod execution_permission;
mod fail_closed_privilege_guard;
mod fanotify_execution_channel;
mod linux_process_control;
mod network_guard;
mod nftables_guard;
mod nix_fanotify;
mod preflight;
mod privilege_guard;
mod privilege_session;
mod privileged_broker;
mod process_closer;
mod process_guard;
mod production_privilege_guard;
mod rustix_pidfd;
mod systemd;

pub use backend::{LinuxBackend, ProductionLinuxBackend};
pub use cgroup_process_class::{FocusCgroupClass, FocusCgroupClassClassifier};
pub use executable_identity::{
    ExecutableIdentityError, observe_executable, observe_open_executable,
};
pub use execution_context::{
    ExecutionContextClassifier, ExecutionContextError, LinuxExecutionFacts,
    enrich_execution_context,
};
pub use execution_fact_collector::{
    ExecutionFactCollectionError, LinuxExecutionFactSource, ProcfsExecutionFactSource,
    collect_execution_observation, collect_running_process, enrich_execution_target_context,
};
pub use execution_permission::{
    ExecutionAttempt, ExecutionPermission, ExecutionPermissionChannel, ExecutionPermissionStep,
    decide_execution_permission, process_next_execution_permission,
};
pub use fail_closed_privilege_guard::FailClosedPrivilegeGuard;
pub use fanotify_execution_channel::{
    FanotifyChannelHealth, FanotifyExecutionChannel, FanotifyExecutionEvent,
    FanotifyPermissionSource,
};
pub use linux_process_control::{
    LinuxProcessControl, LinuxProcessHandle, LinuxProcessInventorySource, ProcessHandleOps,
};
pub use network_guard::{
    FailClosedNetworkGuard, NetworkGuardControl, NetworkGuardError, ProductionNetworkGuard,
};
pub use nftables_guard::{
    FOCUS_NFT_BLOCKED_IPV4_SET, FOCUS_NFT_BLOCKED_IPV6_SET, FOCUS_NFT_FAMILY,
    FOCUS_NFT_OUTPUT_CHAIN, FOCUS_NFT_TABLE, FocusNftablesCommand, FocusNftablesControl,
    FocusNftablesError, FocusNftablesTransaction, SystemNftablesControl, reload_focus_nftables,
    remove_focus_nftables,
};
pub use nix_fanotify::NixFanotifyPermissionSource;
pub use preflight::{
    Health, HostSystemProbe, LinuxError, LinuxPreflightReport, SystemProbe, evaluate_preflight,
    preflight, require_strict_preflight,
};
pub use privilege_guard::{PrivilegeGuardControl, PrivilegeGuardError};
pub use privileged_broker::{
    DockerServiceControl, FailClosedPrivilegeBroker, FailClosedVpnActionControl,
    LinuxPrivilegeBroker, PrivilegeBrokerControl, PrivilegeBrokerError, ProductionPrivilegeBroker,
    SystemctlDockerServiceControl, VpnActionControl,
};
pub use process_closer::{
    ProcessCloseError, ProcessCloseReport, ProcessControl, ProcessLifetime, RunningProcess,
    close_blocked_processes,
};
pub use process_guard::{
    FailClosedProcessGuard, ProcessGuardControl, ProcessGuardError, ProcessGuardMetrics,
    ProductionProcessGuard,
};
pub use production_privilege_guard::ProductionPrivilegeGuard;
pub use rustix_pidfd::RustixPidfdOps;

use std::{
    error::Error,
    fmt, fs, io,
    time::{SystemTime, UNIX_EPOCH},
};

use focus_core::{BootId, EmergencyClockSample};
use nix::time::{ClockId, clock_gettime};

pub const CRATE_NAME: &str = "focus-linux";

const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Error returned while reading Linux clock-integrity sources.
#[derive(Debug)]
pub enum ClockSampleError {
    Io(io::Error),
    InvalidBootId,
    InvalidUptime,
    InvalidMonotonicTime,
    MonotonicClock(nix::errno::Errno),
    SystemTimeBeforeEpoch,
}

impl fmt::Display for ClockSampleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "Linux clock source I/O error: {error}"),
            Self::InvalidBootId => formatter.write_str("invalid Linux boot id"),
            Self::InvalidUptime => formatter.write_str("invalid Linux uptime"),
            Self::InvalidMonotonicTime => formatter.write_str("invalid Linux monotonic time"),
            Self::MonotonicClock(error) => {
                write!(formatter, "Linux monotonic clock error: {error}")
            }
            Self::SystemTimeBeforeEpoch => {
                formatter.write_str("system clock is before the Unix epoch")
            }
        }
    }
}

impl Error for ClockSampleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::MonotonicClock(error) => Some(error),
            Self::InvalidBootId
            | Self::InvalidUptime
            | Self::InvalidMonotonicTime
            | Self::SystemTimeBeforeEpoch => None,
        }
    }
}

impl From<io::Error> for ClockSampleError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Parses Linux `/proc/sys/kernel/random/boot_id` content.
///
/// # Errors
///
/// Returns [`ClockSampleError::InvalidBootId`] when the UUID cannot be decoded.
pub fn parse_boot_id(input: &str) -> Result<BootId, ClockSampleError> {
    let compact: String = input
        .trim()
        .chars()
        .filter(|character| *character != '-')
        .collect();
    if compact.len() != 32 {
        return Err(ClockSampleError::InvalidBootId);
    }

    u128::from_str_radix(&compact, 16)
        .map(BootId)
        .map_err(|_| ClockSampleError::InvalidBootId)
}

/// Parses the first `/proc/uptime` value conservatively to whole seconds.
///
/// This helper remains available for diagnostics and compatibility tests. Production emergency
/// timing uses `CLOCK_BOOTTIME` at nanosecond precision instead of this rounded representation.
///
/// # Errors
///
/// Returns [`ClockSampleError::InvalidUptime`] when the first uptime field is missing or invalid.
pub fn parse_uptime_seconds(input: &str) -> Result<u64, ClockSampleError> {
    let uptime = input
        .split_whitespace()
        .next()
        .ok_or(ClockSampleError::InvalidUptime)?;
    let whole_seconds = uptime
        .split('.')
        .next()
        .ok_or(ClockSampleError::InvalidUptime)?;

    whole_seconds
        .parse()
        .map_err(|_| ClockSampleError::InvalidUptime)
}

fn boottime_nanos() -> Result<u64, ClockSampleError> {
    let time = clock_gettime(ClockId::CLOCK_BOOTTIME).map_err(ClockSampleError::MonotonicClock)?;
    let seconds =
        u64::try_from(time.tv_sec()).map_err(|_| ClockSampleError::InvalidMonotonicTime)?;
    let nanos =
        u64::try_from(time.tv_nsec()).map_err(|_| ClockSampleError::InvalidMonotonicTime)?;
    if nanos >= NANOS_PER_SECOND {
        return Err(ClockSampleError::InvalidMonotonicTime);
    }

    seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(ClockSampleError::InvalidMonotonicTime)
}

/// Samples the current Linux boot, monotonic boot time, and audit wall clock.
///
/// # Errors
///
/// Returns an error when Linux clock sources cannot be read or parsed.
pub fn sample_emergency_clock() -> Result<EmergencyClockSample, ClockSampleError> {
    let boot_id = parse_boot_id(&fs::read_to_string(BOOT_ID_PATH)?)?;
    let monotonic_nanos = boottime_nanos()?;
    let unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ClockSampleError::SystemTimeBeforeEpoch)?
        .as_secs();

    Ok(EmergencyClockSample::new_nanos(
        boot_id,
        monotonic_nanos,
        unix_seconds,
    ))
}
