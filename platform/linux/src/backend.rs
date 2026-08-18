use focus_core::ProcessEnforcementPlan;
use focus_platform::{GuardKind, PlatformBackend, PlatformError, PlatformFuture, PrivilegedAction};

use crate::{
    ExecutionContextClassifier, FailClosedPrivilegeBroker, FailClosedPrivilegeGuard,
    FailClosedProcessGuard, HostSystemProbe, LinuxProcessControl, PrivilegeBrokerControl,
    PrivilegeGuardControl, ProcessControl, ProcessGuardControl, ProcfsExecutionFactSource,
    ProductionPrivilegeBroker, ProductionPrivilegeGuard, ProductionProcessGuard, RustixPidfdOps,
    SystemProbe, close_blocked_processes, evaluate_preflight, require_strict_preflight,
};

/// Production process-control stack used by the Linux backend.
pub type ProductionProcessControl = LinuxProcessControl<ProcfsExecutionFactSource, RustixPidfdOps>;

/// Linux platform backend that owns strict preflight, process closure, and typed enforcement guards.
#[derive(Debug)]
pub struct LinuxBackend<
    P = HostSystemProbe,
    C = ProductionProcessControl,
    G = ProductionProcessGuard,
    V = FailClosedPrivilegeGuard,
    B = FailClosedPrivilegeBroker,
> {
    probe: P,
    process_control: C,
    process_guard: G,
    privilege_guard: V,
    privilege_broker: B,
}

/// Fully wired production Linux backend for one explicitly protected UID.
pub type ProductionLinuxBackend = LinuxBackend<
    HostSystemProbe,
    ProductionProcessControl,
    ProductionProcessGuard,
    ProductionPrivilegeGuard,
    ProductionPrivilegeBroker,
>;

impl Default
    for LinuxBackend<
        HostSystemProbe,
        ProductionProcessControl,
        ProductionProcessGuard,
        FailClosedPrivilegeGuard,
        FailClosedPrivilegeBroker,
    >
{
    fn default() -> Self {
        Self {
            probe: HostSystemProbe,
            process_control: LinuxProcessControl::new(
                ProcfsExecutionFactSource,
                RustixPidfdOps,
                ExecutionContextClassifier::new(Vec::new()),
            ),
            process_guard: ProductionProcessGuard::default(),
            privilege_guard: FailClosedPrivilegeGuard,
            privilege_broker: FailClosedPrivilegeBroker,
        }
    }
}

impl ProductionLinuxBackend {
    /// Creates the production backend scoped to one protected effective UID.
    #[must_use]
    pub fn for_uid(enforced_uid: u32) -> Self {
        Self {
            probe: HostSystemProbe,
            process_control: LinuxProcessControl::for_uid(
                ProcfsExecutionFactSource,
                RustixPidfdOps,
                ExecutionContextClassifier::new(Vec::new()),
                enforced_uid,
            ),
            process_guard: ProductionProcessGuard::for_uid(enforced_uid),
            privilege_guard: ProductionPrivilegeGuard::for_uid(enforced_uid),
            privilege_broker: ProductionPrivilegeBroker::default(),
        }
    }
}

impl<P>
    LinuxBackend<
        P,
        ProductionProcessControl,
        FailClosedProcessGuard,
        FailClosedPrivilegeGuard,
        FailClosedPrivilegeBroker,
    >
{
    /// Creates a Linux backend with an explicit read-only system probe and production process
    /// control. Process and privilege enforcement remain fail-closed until explicit controllers are
    /// supplied.
    #[must_use]
    pub fn with_probe(probe: P) -> Self {
        Self {
            probe,
            process_control: LinuxProcessControl::new(
                ProcfsExecutionFactSource,
                RustixPidfdOps,
                ExecutionContextClassifier::new(Vec::new()),
            ),
            process_guard: FailClosedProcessGuard,
            privilege_guard: FailClosedPrivilegeGuard,
            privilege_broker: FailClosedPrivilegeBroker,
        }
    }
}

impl<P, C>
    LinuxBackend<P, C, FailClosedProcessGuard, FailClosedPrivilegeGuard, FailClosedPrivilegeBroker>
{
    /// Creates a Linux backend with explicit read-only system and process-control dependencies.
    /// Process and privilege enforcement remain fail-closed.
    #[must_use]
    pub const fn with_probe_and_process_control(probe: P, process_control: C) -> Self {
        Self {
            probe,
            process_control,
            process_guard: FailClosedProcessGuard,
            privilege_guard: FailClosedPrivilegeGuard,
            privilege_broker: FailClosedPrivilegeBroker,
        }
    }
}

impl<P, C, G> LinuxBackend<P, C, G, FailClosedPrivilegeGuard, FailClosedPrivilegeBroker> {
    /// Creates a Linux backend with explicit system, process-control, and process-guard
    /// dependencies. Privilege enforcement remains fail-closed.
    #[must_use]
    pub const fn with_probe_process_control_and_guard(
        probe: P,
        process_control: C,
        process_guard: G,
    ) -> Self {
        Self {
            probe,
            process_control,
            process_guard,
            privilege_guard: FailClosedPrivilegeGuard,
            privilege_broker: FailClosedPrivilegeBroker,
        }
    }
}

impl<P, C, G, V> LinuxBackend<P, C, G, V, FailClosedPrivilegeBroker> {
    /// Creates a Linux backend with explicit system, process-control, process-guard, and privilege
    /// guard dependencies. Typed privileged actions remain fail-closed.
    #[must_use]
    pub const fn with_controls(
        probe: P,
        process_control: C,
        process_guard: G,
        privilege_guard: V,
    ) -> Self {
        Self {
            probe,
            process_control,
            process_guard,
            privilege_guard,
            privilege_broker: FailClosedPrivilegeBroker,
        }
    }
}

impl<P, C, G, V, B> LinuxBackend<P, C, G, V, B> {
    /// Creates a Linux backend with every typed enforcement dependency supplied explicitly.
    #[must_use]
    pub const fn with_controls_and_broker(
        probe: P,
        process_control: C,
        process_guard: G,
        privilege_guard: V,
        privilege_broker: B,
    ) -> Self {
        Self {
            probe,
            process_control,
            process_guard,
            privilege_guard,
            privilege_broker,
        }
    }

    /// Returns the process-control dependency for diagnostics and deterministic tests.
    #[must_use]
    pub const fn process_control(&self) -> &C {
        &self.process_control
    }

    /// Returns the continuous process-guard dependency for diagnostics and deterministic tests.
    #[must_use]
    pub const fn process_guard(&self) -> &G {
        &self.process_guard
    }

    /// Returns mutable access to the process-guard dependency for deterministic health tests.
    #[must_use]
    pub const fn process_guard_mut(&mut self) -> &mut G {
        &mut self.process_guard
    }

    /// Returns the privilege-guard dependency for diagnostics and deterministic tests.
    #[must_use]
    pub const fn privilege_guard(&self) -> &V {
        &self.privilege_guard
    }

    /// Returns mutable access to the privilege-guard dependency for deterministic health tests.
    #[must_use]
    pub const fn privilege_guard_mut(&mut self) -> &mut V {
        &mut self.privilege_guard
    }

    /// Returns the typed privilege-broker dependency for diagnostics and deterministic tests.
    #[must_use]
    pub const fn privilege_broker(&self) -> &B {
        &self.privilege_broker
    }
}

impl<P, C, G, V, B> PlatformBackend for LinuxBackend<P, C, G, V, B>
where
    P: SystemProbe,
    C: ProcessControl,
    G: ProcessGuardControl,
    V: PrivilegeGuardControl,
    B: PrivilegeBrokerControl,
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
        plan: &'a ProcessEnforcementPlan,
    ) -> PlatformFuture<'a, ()> {
        let result = self
            .process_guard
            .arm(plan)
            .map_err(|_| PlatformError::GuardFailed(GuardKind::Process));
        Box::pin(async move { result })
    }

    fn verify_process_guard(&mut self, expected_policy_digest: [u8; 32]) -> PlatformFuture<'_, ()> {
        let result = self
            .process_guard
            .verify(expected_policy_digest)
            .map_err(|_| PlatformError::GuardFailed(GuardKind::Process));
        Box::pin(async move { result })
    }

    fn arm_guard(&mut self, guard: GuardKind) -> PlatformFuture<'_, ()> {
        let result = if guard == GuardKind::Privilege {
            self.privilege_guard
                .arm()
                .map_err(|_| PlatformError::GuardFailed(GuardKind::Privilege))
        } else {
            Err(PlatformError::GuardFailed(guard))
        };
        Box::pin(async move { result })
    }

    fn verify_guard(&mut self, guard: GuardKind) -> PlatformFuture<'_, ()> {
        let result = if guard == GuardKind::Privilege {
            self.privilege_guard
                .verify()
                .map_err(|_| PlatformError::GuardFailed(GuardKind::Privilege))
        } else {
            Ok(())
        };
        Box::pin(async move { result })
    }

    fn disarm_guard(&mut self, guard: GuardKind) -> PlatformFuture<'_, ()> {
        let result = match guard {
            GuardKind::Process => self
                .process_guard
                .disarm()
                .map_err(|_| PlatformError::GuardFailed(GuardKind::Process)),
            GuardKind::Privilege => self
                .privilege_guard
                .disarm()
                .map_err(|_| PlatformError::GuardFailed(GuardKind::Privilege)),
            GuardKind::Network | GuardKind::Browser => Ok(()),
        };
        Box::pin(async move { result })
    }

    fn execute_privileged_action(&mut self, action: PrivilegedAction) -> PlatformFuture<'_, ()> {
        let result = self
            .privilege_broker
            .execute(action)
            .map_err(|_| PlatformError::PrivilegedActionFailed(action));
        Box::pin(async move { result })
    }
}
