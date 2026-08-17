//! Platform enforcement interfaces used by the Focus daemon.

use std::{future::Future, pin::Pin};

use focus_core::ProcessEnforcementPlan;

/// Platform guard categories controlled by the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardKind {
    Process,
    Network,
    Browser,
    Privilege,
}

impl GuardKind {
    const fn bit(self) -> u8 {
        match self {
            Self::Process => 1 << 0,
            Self::Network => 1 << 1,
            Self::Browser => 1 << 2,
            Self::Privilege => 1 << 3,
        }
    }
}

/// Closed set of privileged operations that may be brokered by the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedAction {
    DockerStart,
}

/// Error returned by an operating-system enforcement backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformError {
    PreflightFailed,
    GuardFailed(GuardKind),
    CloseBlockedAppsFailed,
    PrivilegedActionFailed(PrivilegedAction),
}

/// Result returned by platform enforcement operations.
pub type PlatformResult<T> = Result<T, PlatformError>;

/// Boxed asynchronous platform operation.
pub type PlatformFuture<'a, T = ()> = Pin<Box<dyn Future<Output = PlatformResult<T>> + Send + 'a>>;

/// Operating-system enforcement contract consumed by the Focus daemon.
pub trait PlatformBackend {
    /// Performs non-mutating readiness checks before a session starts arming.
    fn preflight(&mut self) -> PlatformFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Closes applications forbidden by the exact frozen process plan.
    fn close_blocked_apps<'a>(
        &'a mut self,
        _plan: &'a ProcessEnforcementPlan,
    ) -> PlatformFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Arms the process guard against the exact frozen process plan.
    ///
    /// The default is fail-closed. Implementations must opt in explicitly and must be idempotent
    /// because crash recovery can reapply the same plan after the platform side effect completed
    /// but before the following protected-state write.
    fn arm_process_guard<'a>(
        &'a mut self,
        _plan: &'a ProcessEnforcementPlan,
    ) -> PlatformFuture<'a, ()> {
        Box::pin(async { Err(PlatformError::GuardFailed(GuardKind::Process)) })
    }

    /// Verifies that the process guard is healthy and enforcing the expected frozen policy digest.
    ///
    /// The default is fail-closed so a backend that has not implemented policy-bound process
    /// verification can never make the daemon report `Locked`.
    fn verify_process_guard(
        &mut self,
        _expected_policy_digest: [u8; 32],
    ) -> PlatformFuture<'_, ()> {
        Box::pin(async { Err(PlatformError::GuardFailed(GuardKind::Process)) })
    }

    /// Arms one non-process enforcement guard.
    ///
    /// The daemon uses [`Self::arm_process_guard`] for [`GuardKind::Process`]. Implementations
    /// should still fail closed if generic process arming is attempted elsewhere.
    fn arm_guard(&mut self, guard: GuardKind) -> PlatformFuture<'_, ()>;

    /// Verifies one non-process guard before the daemon reports Locked.
    ///
    /// The daemon uses [`Self::verify_process_guard`] for [`GuardKind::Process`].
    fn verify_guard(&mut self, _guard: GuardKind) -> PlatformFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Reverses one previously applied guard during best-effort arming compensation.
    ///
    /// Implementations must be idempotent so retrying an uncertain compensation step cannot create
    /// a new platform side effect. Process compensation also uses this method after a successful
    /// typed process arm.
    fn disarm_guard(&mut self, _guard: GuardKind) -> PlatformFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Executes one explicitly approved privileged action.
    ///
    /// The default is fail-closed. The typed action contains no arbitrary command, argument vector,
    /// or filesystem-write payload.
    fn execute_privileged_action(&mut self, action: PrivilegedAction) -> PlatformFuture<'_, ()> {
        Box::pin(async move { Err(PlatformError::PrivilegedActionFailed(action)) })
    }
}

/// Production-safe placeholder used until a real operating-system backend is available.
///
/// This backend deliberately refuses every guard so a daemon can never advertise `Locked` merely
/// because enforcement has not yet been implemented.
#[derive(Debug, Default, Clone, Copy)]
pub struct FailClosedBackend;

impl PlatformBackend for FailClosedBackend {
    fn arm_guard(&mut self, guard: GuardKind) -> PlatformFuture<'_, ()> {
        Box::pin(async move { Err(PlatformError::GuardFailed(guard)) })
    }
}

/// Deterministic backend used by daemon tests without touching the host system.
#[derive(Debug, Default)]
pub struct FakeBackend {
    failing_guards: u8,
    failing_verifications: u8,
    failing_disarms: u8,
    fail_close_blocked_apps: bool,
    active_guards: u8,
    armed: Vec<GuardKind>,
    disarmed: Vec<GuardKind>,
    process_policy_digest: Option<[u8; 32]>,
    privileged_actions: Vec<PrivilegedAction>,
}

impl FakeBackend {
    /// Configures one guard to fail when it is armed.
    pub const fn fail_guard(&mut self, guard: GuardKind) {
        self.failing_guards |= guard.bit();
    }

    /// Configures one guard verification to fail.
    pub const fn fail_verification(&mut self, guard: GuardKind) {
        self.failing_verifications |= guard.bit();
    }

    /// Configures one compensation disarm attempt to fail.
    pub const fn fail_disarm(&mut self, guard: GuardKind) {
        self.failing_disarms |= guard.bit();
    }

    /// Configures the blocked-application close step to fail.
    pub const fn fail_close_blocked_apps(&mut self) {
        self.fail_close_blocked_apps = true;
    }

    /// Marks a guard as already active without recording a new arm operation.
    ///
    /// This models a crash after the platform effect completed but before the next protected-state
    /// write. A prearmed process guard has no policy digest and therefore cannot pass typed process
    /// verification until it is rearmed against a frozen plan.
    pub const fn prearm_guard(&mut self, guard: GuardKind) {
        self.active_guards |= guard.bit();
    }

    /// Returns whether a guard is currently active in the fake platform state.
    #[must_use]
    pub const fn guard_is_armed(&self, guard: GuardKind) -> bool {
        self.active_guards & guard.bit() != 0
    }

    /// Returns guards that produced a new successful platform arm effect, in order.
    #[must_use]
    pub fn armed(&self) -> &[GuardKind] {
        &self.armed
    }

    /// Returns guards whose disarm was attempted, in compensation order.
    #[must_use]
    pub fn disarmed(&self) -> &[GuardKind] {
        &self.disarmed
    }

    /// Returns the frozen policy digest currently attached to the fake process guard.
    #[must_use]
    pub const fn process_policy_digest(&self) -> Option<[u8; 32]> {
        self.process_policy_digest
    }

    /// Returns privileged actions executed through the typed fake broker.
    #[must_use]
    pub fn privileged_actions(&self) -> &[PrivilegedAction] {
        &self.privileged_actions
    }

    const fn should_fail(mask: u8, guard: GuardKind) -> bool {
        mask & guard.bit() != 0
    }
}

impl PlatformBackend for FakeBackend {
    fn close_blocked_apps<'a>(
        &'a mut self,
        _plan: &'a ProcessEnforcementPlan,
    ) -> PlatformFuture<'a, ()> {
        let should_fail = self.fail_close_blocked_apps;
        Box::pin(async move {
            if should_fail {
                Err(PlatformError::CloseBlockedAppsFailed)
            } else {
                Ok(())
            }
        })
    }

    fn arm_process_guard<'a>(
        &'a mut self,
        plan: &'a ProcessEnforcementPlan,
    ) -> PlatformFuture<'a, ()> {
        let guard = GuardKind::Process;
        let should_fail = Self::should_fail(self.failing_guards, guard);
        if !should_fail {
            self.process_policy_digest = Some(plan.policy_digest());
            if !self.guard_is_armed(guard) {
                self.active_guards |= guard.bit();
                self.armed.push(guard);
            }
        }
        Box::pin(async move {
            if should_fail {
                Err(PlatformError::GuardFailed(guard))
            } else {
                Ok(())
            }
        })
    }

    fn verify_process_guard(&mut self, expected_policy_digest: [u8; 32]) -> PlatformFuture<'_, ()> {
        let guard = GuardKind::Process;
        let should_fail = Self::should_fail(self.failing_verifications, guard)
            || !self.guard_is_armed(guard)
            || self.process_policy_digest != Some(expected_policy_digest);
        Box::pin(async move {
            if should_fail {
                Err(PlatformError::GuardFailed(guard))
            } else {
                Ok(())
            }
        })
    }

    fn arm_guard(&mut self, guard: GuardKind) -> PlatformFuture<'_, ()> {
        if guard == GuardKind::Process {
            return Box::pin(async { Err(PlatformError::GuardFailed(GuardKind::Process)) });
        }
        let should_fail = Self::should_fail(self.failing_guards, guard);
        if !should_fail && !self.guard_is_armed(guard) {
            self.active_guards |= guard.bit();
            self.armed.push(guard);
        }
        Box::pin(async move {
            if should_fail {
                Err(PlatformError::GuardFailed(guard))
            } else {
                Ok(())
            }
        })
    }

    fn verify_guard(&mut self, guard: GuardKind) -> PlatformFuture<'_, ()> {
        if guard == GuardKind::Process {
            return Box::pin(async { Err(PlatformError::GuardFailed(GuardKind::Process)) });
        }
        let should_fail =
            Self::should_fail(self.failing_verifications, guard) || !self.guard_is_armed(guard);
        Box::pin(async move {
            if should_fail {
                Err(PlatformError::GuardFailed(guard))
            } else {
                Ok(())
            }
        })
    }

    fn disarm_guard(&mut self, guard: GuardKind) -> PlatformFuture<'_, ()> {
        let should_fail = Self::should_fail(self.failing_disarms, guard);
        self.disarmed.push(guard);
        if !should_fail {
            self.active_guards &= !guard.bit();
            if guard == GuardKind::Process {
                self.process_policy_digest = None;
            }
        }
        Box::pin(async move {
            if should_fail {
                Err(PlatformError::GuardFailed(guard))
            } else {
                Ok(())
            }
        })
    }

    fn execute_privileged_action(&mut self, action: PrivilegedAction) -> PlatformFuture<'_, ()> {
        self.privileged_actions.push(action);
        Box::pin(async { Ok(()) })
    }
}
