use focus_core::ProcessEnforcementPlan;
use focus_platform::{GuardKind, PlatformBackend, PlatformError, PlatformFuture};

use crate::{
    ExecutionContextClassifier, HostSystemProbe, LinuxProcessControl, ProcessControl,
    ProcfsExecutionFactSource, RustixPidfdOps, SystemProbe, close_blocked_processes,
    evaluate_preflight, require_strict_preflight,
};

/// Production process-control stack used by the Linux backend.
pub type ProductionProcessControl =
    LinuxProcessControl<ProcfsExecutionFactSource, RustixPidfdOps>;

/// Linux platform backend that owns strict preflight and process closure.
///
/// Process execution prevention remains fail-closed until the fanotify guard is implemented.
#[derive(Debug)]
pub struct LinuxBackend<P = HostSystemProbe, C = ProductionProcessControl> {
    probe: P,
    process_control: C,
}

impl Default for LinuxBackend<HostSystemProbe, ProductionProcessControl> {
    fn default() -> Self {
        Self {
            probe: HostSystemProbe,
            process_control: LinuxProcessControl::new(
                ProcfsExecutionFactSource,
                RustixPidfdOps,
                ExecutionContextClassifier::new(Vec::new()),
            ),
        }
    }
}

impl<P> LinuxBackend<P, ProductionProcessControl> {
    /// Creates a Linux backend with an explicit read-only system probe and production process
    /// control.
    #[must_use]
    pub fn with_probe(probe: P) -> Self {
        Self {
            probe,
            process_control: LinuxProcessControl::new(
                ProcfsExecutionFactSource,
                RustixPidfdOps,
                ExecutionContextClassifier::new(Vec::new()),
            ),
        }
    }
}

impl<P, C> LinuxBackend<P, C> {
    /// Creates a Linux backend with explicit read-only system and process-control dependencies.
    #[must_use]
    pub const fn with_probe_and_process_control(probe: P, process_control: C) -> Self {
        Self {
            probe,
            process_control,
        }
    }

    /// Returns the process-control dependency for diagnostics and deterministic tests.
    #[must_use]
    pub const fn process_control(&self) -> &C {
        &self.process_control
    }
}

impl<P, C> PlatformBackend for LinuxBackend<P, C>
where
    P: SystemProbe,
    C: ProcessControl,
{
    fn preflight(&mut self) -> PlatformFuture<'_, ()> {
        let result = evaluate_preflight(&self.probe)
            .and_then(|report| require_strict_preflight(&report))
            .map_err(|_| PlatformError::PreflightFailed);
        Box::pin(async move { result })
    }

    fn close_blocked_apps<'a>(
        &'a mut self,
        plan: &'a ProcessEnforcementPlan,
    ) -> PlatformFuture<'a, ()> {
        let result = close_blocked_processes(&mut self.process_control, plan)
            .map(|_| ())
            .map_err(|_| PlatformError::CloseBlockedAppsFailed);
        Box::pin(async move { result })
    }

    fn arm_process_guard<'a>(
        &'a mut self,
        _plan: &'a ProcessEnforcementPlan,
    ) -> PlatformFuture<'a, ()> {
        Box::pin(async { Err(PlatformError::GuardFailed(GuardKind::Process)) })
    }

    fn verify_process_guard(
        &mut self,
        _expected_policy_digest: [u8; 32],
    ) -> PlatformFuture<'_, ()> {
        Box::pin(async { Err(PlatformError::GuardFailed(GuardKind::Process)) })
    }

    fn arm_guard(&mut self, guard: GuardKind) -> PlatformFuture<'_, ()> {
        Box::pin(async move { Err(PlatformError::GuardFailed(guard)) })
    }
}
