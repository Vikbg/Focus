//! Linux-specific Focus enforcement backend.

use std::{
    error::Error,
    fmt, fs, io,
    time::{SystemTime, UNIX_EPOCH},
};

use focus_core::{BootId, EmergencyClockSample};

pub const CRATE_NAME: &str = "focus-linux";

const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const UPTIME_PATH: &str = "/proc/uptime";

/// Error returned while reading Linux clock-integrity sources.
#[derive(Debug)]
pub enum ClockSampleError {
    Io(io::Error),
    InvalidBootId,
    InvalidUptime,
    SystemTimeBeforeEpoch,
}

impl fmt::Display for ClockSampleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "Linux clock source I/O error: {error}"),
            Self::InvalidBootId => formatter.write_str("invalid Linux boot id"),
            Self::InvalidUptime => formatter.write_str("invalid Linux uptime"),
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
            Self::InvalidBootId | Self::InvalidUptime | Self::SystemTimeBeforeEpoch => None,
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
    let compact: String = input.trim().chars().filter(|character| *character != '-').collect();
    if compact.len() != 32 {
        return Err(ClockSampleError::InvalidBootId);
    }

    u128::from_str_radix(&compact, 16)
        .map(BootId)
        .map_err(|_| ClockSampleError::InvalidBootId)
}

/// Parses the first `/proc/uptime` value conservatively to whole seconds.
///
/// Fractional seconds are discarded so the emergency wait is never shortened by rounding.
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

/// Samples the current Linux boot, monotonic boot uptime, and audit wall clock.
///
/// # Errors
///
/// Returns an error when Linux clock sources cannot be read or parsed.
pub fn sample_emergency_clock() -> Result<EmergencyClockSample, ClockSampleError> {
    let boot_id = parse_boot_id(&fs::read_to_string(BOOT_ID_PATH)?)?;
    let monotonic_seconds = parse_uptime_seconds(&fs::read_to_string(UPTIME_PATH)?)?;
    let unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ClockSampleError::SystemTimeBeforeEpoch)?
        .as_secs();

    Ok(EmergencyClockSample::new(
        boot_id,
        monotonic_seconds,
        unix_seconds,
    ))
}
