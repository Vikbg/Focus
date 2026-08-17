use std::{
    io,
    os::fd::{AsFd, BorrowedFd},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use focus_core::ProcessEnforcementPlan;
use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::eventfd::{EfdFlags, EventFd},
};

use crate::{
    ExecutionContextClassifier, FanotifyExecutionChannel, LinuxProcessControl,
    NixFanotifyPermissionSource, ProcfsExecutionFactSource, RustixPidfdOps,
    close_blocked_processes, process_next_execution_permission,
};

const WATCHDOG_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessGuardWake {
    Permission,
    Stop,
    Watchdog,
}

fn wait_for_process_guard_wake(
    permission_fd: BorrowedFd<'_>,
    stop_fd: BorrowedFd<'_>,
    watchdog_interval: Duration,
) -> io::Result<ProcessGuardWake> {
    let deadline = Instant::now()
        .checked_add(watchdog_interval)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "watchdog deadline overflow"))?;
    let mut fds = [
        PollFd::new(permission_fd, PollFlags::POLLIN),
        PollFd::new(stop_fd, PollFlags::POLLIN),
    ];
    let fatal = PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(ProcessGuardWake::Watchdog);
        }
        let timeout = PollTimeout::try_from(remaining).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "watchdog interval is too large",
            )
        })?;

        match poll(&mut fds, timeout) {
            Ok(0) => return Ok(ProcessGuardWake::Watchdog),
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

/// Snapshot of process-guard performance measurements for the current arm cycle.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProcessGuardMetrics {
    permission_decisions: u64,
    total_decision_latency_nanos: u64,
    max_decision_latency_nanos: u64,
    watchdog_wakeups: u64,
}

impl ProcessGuardMetrics {
    /// Returns the number of non-idle permission decisions completed by the worker.
    #[must_use]
    pub const fn permission_decisions(self) -> u64 {
        self.permission_decisions
    }

    /// Returns the accumulated worker-side permission decision latency.
    #[must_use]
    pub const fn total_decision_latency(self) -> Duration {
        Duration::from_nanos(self.total_decision_latency_nanos)
    }

    /// Returns the largest worker-side permission decision latency observed so far.
    #[must_use]
    pub const fn max_decision_latency(self) -> Duration {
        Duration::from_nanos(self.max_decision_latency_nanos)
    }

    /// Returns the average worker-side permission decision latency when at least one decision ran.
    #[must_use]
    pub fn average_decision_latency(self) -> Option<Duration> {
        if self.permission_decisions == 0 {
            return None;
        }
        Some(Duration::from_nanos(
            self.total_decision_latency_nanos / self.permission_decisions,
        ))
    }

    /// Returns the number of idle watchdog deadline wakeups observed by the worker.
    #[must_use]
    pub const fn watchdog_wakeups(self) -> u64 {
        self.watchdog_wakeups
    }
}

#[derive(Debug, Default)]
struct ProcessGuardMetricCounters {
    permission_decisions: AtomicU64,
    total_decision_latency_nanos: AtomicU64,
    max_decision_latency_nanos: AtomicU64,
    watchdog_wakeups: AtomicU64,
}

impl ProcessGuardMetricCounters {
    fn record_decision(&self, latency: Duration) {
        let latency_nanos = u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX);
        self.permission_decisions.fetch_add(1, Ordering::Relaxed);
        self.total_decision_latency_nanos
            .fetch_add(latency_nanos, Ordering::Relaxed);
        self.max_decision_latency_nanos
            .fetch_max(latency_nanos, Ordering::Relaxed);
    }

    fn record_watchdog_wakeup(&self) {
        self.watchdog_wakeups.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> ProcessGuardMetrics {
        ProcessGuardMetrics {
            permission_decisions: self.permission_decisions.load(Ordering::Relaxed),
            total_decision_latency_nanos: self.total_decision_latency_nanos.load(Ordering::Relaxed),
            max_decision_latency_nanos: self.max_decision_latency_nanos.load(Ordering::Relaxed),
            watchdog_wakeups: self.watchdog_wakeups.load(Ordering::Relaxed),
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
/// thread. A periodic procfs and pidfd watchdog closes explicitly blocked processes as a second
/// layer. Any transport, classification, inventory, or termination failure makes the worker
/// unhealthy so verification can never report a false success.
#[derive(Debug)]
pub struct ProductionProcessGuard {
    mounts: Vec<PathBuf>,
    enforced_uid: Option<u32>,
    metrics: Arc<ProcessGuardMetricCounters>,
    worker: Option<ProcessGuardWorker>,
}

impl Default for ProductionProcessGuard {
    fn default() -> Self {
        Self {
            mounts: vec![PathBuf::from("/")],
            enforced_uid: None,
            metrics: Arc::new(ProcessGuardMetricCounters::default()),
            worker: None,
        }
    }
}

impl ProductionProcessGuard {
    /// Creates a production guard over an explicit set of mounted filesystem roots.
    ///
    /// This constructor is primarily useful for privileged VM fixtures. Production defaults to the
    /// root mount and the runtime watchdog remains responsible for blocked processes that appear on
    /// execution paths outside the marked mount.
    #[must_use]
    pub fn for_mounts<I, P>(mounts: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        Self {
            mounts: mounts.into_iter().map(Into::into).collect(),
            enforced_uid: None,
            metrics: Arc::new(ProcessGuardMetricCounters::default()),
            worker: None,
        }
    }

    /// Creates a production guard scoped to one protected effective UID.
    #[must_use]
    pub fn for_uid(enforced_uid: u32) -> Self {
        Self {
            mounts: vec![PathBuf::from("/")],
            enforced_uid: Some(enforced_uid),
            metrics: Arc::new(ProcessGuardMetricCounters::default()),
            worker: None,
        }
    }

    /// Returns the protected effective UID when this guard is user-scoped.
    #[must_use]
    pub const fn enforced_uid(&self) -> Option<u32> {
        self.enforced_uid
    }

    /// Returns a lock-free snapshot of the current arm cycle performance measurements.
    #[must_use]
    pub fn metrics(&self) -> ProcessGuardMetrics {
        self.metrics.snapshot()
    }

    fn execution_channel(
        &self,
        source: NixFanotifyPermissionSource,
    ) -> FanotifyExecutionChannel<NixFanotifyPermissionSource, ProcfsExecutionFactSource> {
        if let Some(enforced_uid) = self.enforced_uid {
            FanotifyExecutionChannel::for_uid(
                source,
                ProcfsExecutionFactSource,
                ExecutionContextClassifier::new(Vec::new()),
                enforced_uid,
            )
        } else {
            FanotifyExecutionChannel::new(
                source,
                ProcfsExecutionFactSource,
                ExecutionContextClassifier::new(Vec::new()),
            )
        }
    }

    fn watchdog_control(&self) -> LinuxProcessControl<ProcfsExecutionFactSource, RustixPidfdOps> {
        if let Some(enforced_uid) = self.enforced_uid {
            LinuxProcessControl::for_uid(
                ProcfsExecutionFactSource,
                RustixPidfdOps,
                ExecutionContextClassifier::new(Vec::new()),
                enforced_uid,
            )
        } else {
            LinuxProcessControl::new(
                ProcfsExecutionFactSource,
                RustixPidfdOps,
                ExecutionContextClassifier::new(Vec::new()),
            )
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
        let mut channel = self.execution_channel(source);
        let mut watchdog_control = self.watchdog_control();
        let frozen_plan = plan.clone();
        let healthy = Arc::new(AtomicBool::new(true));
        let stop_requested = Arc::new(AtomicBool::new(false));
        let stop_event = Arc::new(
            EventFd::from_flags(EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK)
                .map_err(|_| ProcessGuardError::Unavailable)?,
        );
        let metrics = Arc::new(ProcessGuardMetricCounters::default());
        self.metrics = Arc::clone(&metrics);
        let worker_healthy = Arc::clone(&healthy);
        let worker_stop_requested = Arc::clone(&stop_requested);
        let worker_stop_event = Arc::clone(&stop_event);
        let worker_metrics = Arc::clone(&metrics);

        let handle = thread::Builder::new()
            .name("focus-process-guard".to_owned())
            .spawn(move || {
                let mut next_watchdog = Instant::now() + WATCHDOG_INTERVAL;

                while !worker_stop_requested.load(Ordering::Acquire) {
                    let decision_started = Instant::now();
                    let Ok(step) = process_next_execution_permission(&mut channel, &frozen_plan)
                    else {
                        worker_healthy.store(false, Ordering::Release);
                        break;
                    };
                    if step != crate::ExecutionPermissionStep::Idle {
                        worker_metrics.record_decision(decision_started.elapsed());
                    }

                    if Instant::now() >= next_watchdog {
                        if close_blocked_processes(&mut watchdog_control, &frozen_plan).is_err() {
                            worker_healthy.store(false, Ordering::Release);
                            break;
                        }
                        next_watchdog = Instant::now() + WATCHDOG_INTERVAL;
                    }

                    if step == crate::ExecutionPermissionStep::Idle {
                        let remaining = next_watchdog.saturating_duration_since(Instant::now());
                        match wait_for_process_guard_wake(
                            channel.source_fd(),
                            worker_stop_event.as_fd(),
                            remaining,
                        ) {
                            Ok(ProcessGuardWake::Permission) => {}
                            Ok(ProcessGuardWake::Stop) => break,
                            Ok(ProcessGuardWake::Watchdog) => {
                                worker_metrics.record_watchdog_wakeup();
                                if close_blocked_processes(&mut watchdog_control, &frozen_plan)
                                    .is_err()
                                {
                                    worker_healthy.store(false, Ordering::Release);
                                    break;
                                }
                                next_watchdog = Instant::now() + WATCHDOG_INTERVAL;
                            }
                            Err(_) => {
                                worker_healthy.store(false, Ordering::Release);
                                break;
                            }
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
    use std::{io::Write, os::fd::AsFd, os::unix::net::UnixStream, time::Duration};

    use super::{
        ProcessGuardMetricCounters, ProcessGuardMetrics, ProcessGuardWake,
        wait_for_process_guard_wake,
    };

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

    #[test]
    fn metric_counters_accumulate_decisions_and_watchdog_wakeups() {
        let counters = ProcessGuardMetricCounters::default();
        counters.record_decision(Duration::from_millis(2));
        counters.record_decision(Duration::from_millis(4));
        counters.record_watchdog_wakeup();

        let metrics = counters.snapshot();
        assert_eq!(metrics.permission_decisions(), 2);
        assert_eq!(metrics.total_decision_latency(), Duration::from_millis(6));
        assert_eq!(metrics.max_decision_latency(), Duration::from_millis(4));
        assert_eq!(
            metrics.average_decision_latency(),
            Some(Duration::from_millis(3))
        );
        assert_eq!(metrics.watchdog_wakeups(), 1);
        assert_ne!(metrics, ProcessGuardMetrics::default());
    }
}
