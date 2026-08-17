use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use focus_core::ProcessEnforcementPlan;

use crate::{
    ExecutionContextClassifier, FanotifyExecutionChannel, NixFanotifyPermissionSource,
    ProcfsExecutionFactSource, process_next_execution_permission,
};

const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(2);

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
    stop: Arc<AtomicBool>,
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
        let Some(worker) = self.worker.take() else {
            return Ok(());
        };

        worker.stop.store(true, Ordering::Release);
        worker
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
        let stop = Arc::new(AtomicBool::new(false));
        let worker_healthy = Arc::clone(&healthy);
        let worker_stop = Arc::clone(&stop);

        let handle = thread::Builder::new()
            .name("focus-process-guard".to_owned())
            .spawn(move || {
                while !worker_stop.load(Ordering::Acquire) {
                    match process_next_execution_permission(&mut channel, &frozen_plan) {
                        Ok(crate::ExecutionPermissionStep::Idle) => {
                            thread::sleep(IDLE_POLL_INTERVAL);
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
            stop,
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
