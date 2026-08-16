use std::{io, os::fd::OwnedFd};

use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};

use crate::ProcessHandleOps;

/// Safe Linux pidfd operations used by production process control.
#[derive(Debug, Default, Clone, Copy)]
pub struct RustixPidfdOps;

impl ProcessHandleOps for RustixPidfdOps {
    type Handle = OwnedFd;

    fn open_process(&mut self, pid: u32) -> io::Result<Self::Handle> {
        let raw_pid = i32::try_from(pid).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "process ID does not fit pid_t")
        })?;
        let pid = Pid::from_raw(raw_pid).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "process ID must be positive")
        })?;

        pidfd_open(pid, PidfdFlags::empty()).map_err(io::Error::from)
    }

    fn terminate_process(&mut self, handle: &Self::Handle) -> io::Result<()> {
        pidfd_send_signal(handle, Signal::TERM).map_err(io::Error::from)
    }
}
