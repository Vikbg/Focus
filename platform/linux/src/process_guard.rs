use std::{
    io,
    os::fd::{AsFd, BorrowedFd},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};

use focus_core::ProcessEnforcementPlan;
use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::eventfd::{EfdFlags, EventFd},
};

use crate::{
    ExecutionContextClassifier, FanotifyExecutionChannel, NixFanotifyPermissionSource,
    ProcfsExecutionFactSource, process_next_execution_permission,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessGuardWake {
    Permission,
    Stop,
}

fn wait_for_process_guard_wake(
    permission_fd: BorrowedFd<'_>,
    stop_fd: BorrowedFd<'_>,
) -> io::Result<ProcessGuardWake> {
    let mut fds = [
        PollFd::new(permission_fd, PollFlags::POLLIN),
        PollFd::new(stop_fd, PollFlags::POLLIN),
    ];
    let fatal = PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL;

    loop {
        match poll(&mut fds, PollTimeout::NONE) {
            Ok(_) => {
                let permission_events = fds[0].revents().unwrap_or_else(PollFlags::empty);
                let stop_events = fds[1].revents().unwrap_or_else(PollFlags::empty);

                if permission_events.intersects(fatal) || stop_events.intersects(fatal) {
                    return Err(io::Error::other(
                        "process guard readiness descriptor became unhealthy",
                    ));
                }
                if stop_events.contains(PollFlags::POLLIN) {
                    return Ok(ProcessGuardWake::Stop);
                }
                if permission_events.contains(PollFlags::POLLIN) {
                    return Ok(ProcessGuardWake::Permission);
                }
            }
            Err(Errno::EINTR) => {}
            Err(error) => return Err(io::Error::from_raw_os_error(error as i32)),
        }
    }
}

/// Error returned by the continuous Linux process-execution guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessGuardError {
    Unavailable,
    Unhealthy,
    DisarmFailed,
}

/// Continuous process-execution enforcement owned by the Linux backend.
///
/// Implementations must make `arm` idempotent for the same frozen policy digest. Recovery can
/// repeat the call after the platform effect completed but before protected daemon state advanced.
pub trait ProcessGuardControl {
    /// Arms continuous execution prevention against the exact frozen process plan.
    ///
    /// # Errors
    ///
    /// Returns an error when the guard cannot initialize or cannot replace an unhealthy worker.
    fn arm(&mut self, plan: &ProcessEnforcementPlan) -> Result<(), ProcessGuardError>;

    /// Verifies that the guard is healthy and enforcing the expected frozen policy digest.
    ///
    /// # Errors
    ///
    /// Returns an error when no healthy worker is enforcing the expected policy digest.
    fn verify(&mut self, expected_policy_digest: [u8; 32]) -> Result<(), ProcessGuardError>;

    /// Stops the continuous process guard. The operation must be idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error when an active worker cannot be stopped cleanly.
    fn disarm(&mut self) -> Result<(), ProcessGuardError>;
}

/// Default controller used only when production process enforcement was not explicitly wired.
///
/// It deliberately refuses arm and verify so Linux can never report the Process guard healthy by
/// construction alone.
#[derive(Debug, Default, Clone, Copy)]
pub struct FailClosedProcessGuard;

impl ProcessGuardControl for FailClosedProcessGuard {
    fn arm(&mut self, _plan: &ProcessEnforcementPlan) -> Result<(), ProcessGuardError> {
        Err(ProcessGuardError::Unavailable)
    }

    fn verify(&mut self, _expected_policy_digest: [u8; 32]) -> Result<(), ProcessGuardError> {
        Err(ProcessGuardError::Unhealthy)
    }

    fn disarm(&mut self) -> Result<(), ProcessGuardError> {
        Ok(())
    }
}

#[derive(Debug)]
struct ProcessGuardWorker {
    policy_digest: [u8; 32],
    healthy: Arc<AtomicBool>,
    stop_requested: Arc<AtomicBool>,
    stop_event: Arc<EventFd>,
    handle: JoinHandle<()>,
}

impl ProcessGuardWorker {
    fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire) && !self.handle.is_finished()
    }
}

/// Production fanotify-backed process execution guard.
///
/// The guard creates the privileged fanotify permission source only when a protected session is
/// armed. Permission events are evaluated against the immutable process plan on a dedicated worker
/// thread. Any transport or classification failure makes the worker unhealthy so verification can
/// never report a false success.
#[derive(Debug)]
pub struct ProductionProcessGuard {
    mounts: Vec<PathBuf>,
    worker: Option<ProcessGuardWorker>,
}

impl Default for ProductionProcessGuard {
    fn default() -> Self {
        Self {
            mounts: vec![PathBuf::from("/")],
            worker: None,
        }
    }
}

impl ProductionProcessGuard {
    /// Creates a production guard over an explicit set of mounted filesystem roots.
    ///
    /// This constructor is primarily useful for privileged VM fixtures. Production defaults to the
    /// root mount and later watchdog coverage remains responsible for execution paths that appear on
    /// mounts created after arming.
    #[must_use]
    pub fn for_mounts<I, P>(mounts: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        Self {
            mounts: mounts.into_iter().map(Into::into).collect(),
            worker: None,
        }
    }

    fn stop_worker(&mut self) -> Result<(), ProcessGuardError> {
        let Some(worker) = self.worker.as_ref() else {
            return Ok(());
        };

        worker.stop_requested.store(true, Ordering::Release);
        if !worker.handle.is_finished() {
            worker
                .stop_event
                .write(1)
                .map_err(|_| ProcessGuardError::DisarmFailed)?;
        }

        self.worker
            .take()
            .expect("process guard worker exists after immutable borrow")
            .handle
            .join()
            .map_err(|_| ProcessGuardError::DisarmFailed)
    }
}

impl ProcessGuardControl for ProductionProcessGuard {
    fn arm(&mut self, plan: &ProcessEnforcementPlan) -> Result<(), ProcessGuardError> {
        let policy_digest = plan.policy_digest();
        if let Some(worker) = self.worker.as_ref() {
            if worker.policy_digest == policy_digest && worker.is_healthy() {
                return Ok(());
            }
            self.stop_worker()?;
        }

        if self.mounts.is_empty() {
            return Err(ProcessGuardError::Unavailable);
        }

        let source = NixFanotifyPermissionSource::new_for_mounts(self.mounts.iter())
            .map_err(|_| ProcessGuardError::Unavailable)?;
        let mut channel = FanotifyExecutionChannel::new(
            source,
            ProcfsExecutionFactSource,
            ExecutionContextClassifier::new(Vec::new()),
        );
        let frozen_plan = plan.clone();
        let healthy = Arc::new(AtomicBool::new(true));
        let stop_requested = Arc::new(AtomicBool::new(false));
        let stop_event = Arc::new(
            EventFd::from_flags(EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK)
                .map_err(|_| ProcessGuardError::Unavailable)?,
        );
        let worker_healthy = Arc::clone(&healthy);
        let worker_stop_requested = Arc::clone(&stop_requested);
        let worker_stop_event = Arc::clone(&stop_event);

        let handle = thread::Builder::new()
            .name("focus-process-guard".to_owned())
            .spawn(move || {
                while !worker_stop_requested.load(Ordering::Acquire) {
                    match process_next_execution_permission(&mut channel, &frozen_plan) {
                        Ok(crate::ExecutionPermissionStep::Idle) => {
                            match wait_for_process_guard_wake(
                                channel.source_fd(),
                                worker_stop_event.as_fd(),
                            ) {
                                Ok(ProcessGuardWake::Permission) => {}
                                Ok(ProcessGuardWake::Stop) => break,
                                Err(_) => {
                                    worker_healthy.store(false, Ordering::Release);
                                    break;
                                }
                            }
                        }
                        Ok(
                            crate::ExecutionPermissionStep::Allowed
                            | crate::ExecutionPermissionStep::Denied,
                        ) => {}
                        Err(_) => {
                            worker_healthy.store(false, Ordering::Release);
                            break;
                        }
                    }
                }
            })
            .map_err(|_| ProcessGuardError::Unavailable)?;

        self.worker = Some(ProcessGuardWorker {
            policy_digest,
            healthy,
            stop_requested,
            stop_event,
            handle,
        });
        Ok(())
    }

    fn verify(&mut self, expected_policy_digest: [u8; 32]) -> Result<(), ProcessGuardError> {
        let Some(worker) = self.worker.as_ref() else {
            return Err(ProcessGuardError::Unhealthy);
        };
        if worker.policy_digest != expected_policy_digest || !worker.is_healthy() {
            return Err(ProcessGuardError::Unhealthy);
        }
        Ok(())
    }

    fn disarm(&mut self) -> Result<(), ProcessGuardError> {
        self.stop_worker()
    }
}

impl Drop for ProductionProcessGuard {
    fn drop(&mut self) {
        let _ = self.disarm();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        os::fd::AsFd,
        os::unix::net::UnixStream,
        time::Duration,
    };

    use super::{ProcessGuardWake, wait_for_process_guard_wake};

    #[test]
    fn event_wait_wakes_when_permission_fd_becomes_readable() {
        let (mut permission_writer, permission_reader) = UnixStream::pair().unwrap();
        let (_stop_writer, stop_reader) = UnixStream::pair().unwrap();
        permission_writer.write_all(&[1]).unwrap();

        assert_eq!(
            wait_for_process_guard_wake(
                permission_reader.as_fd(),
                stop_reader.as_fd(),
                Duration::from_secs(60),
            )
            .unwrap(),
            ProcessGuardWake::Permission
        );
    }

    #[test]
    fn event_wait_wakes_when_stop_fd_becomes_readable() {
        let (_permission_writer, permission_reader) = UnixStream::pair().unwrap();
        let (mut stop_writer, stop_reader) = UnixStream::pair().unwrap();
        stop_writer.write_all(&[1]).unwrap();

        assert_eq!(
            wait_for_process_guard_wake(
                permission_reader.as_fd(),
                stop_reader.as_fd(),
                Duration::from_secs(60),
            )
            .unwrap(),
            ProcessGuardWake::Stop
        );
    }

    #[test]
    fn event_wait_wakes_for_runtime_watchdog_deadline() {
        let (_permission_writer, permission_reader) = UnixStream::pair().unwrap();
        let (_stop_writer, stop_reader) = UnixStream::pair().unwrap();

        assert_eq!(
            wait_for_process_guard_wake(
                permission_reader.as_fd(),
                stop_reader.as_fd(),
                Duration::from_millis(1),
            )
            .unwrap(),
            ProcessGuardWake::Watchdog
        );
    }
}
