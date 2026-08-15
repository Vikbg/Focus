//! Platform enforcement interfaces used by the Focus daemon.

use std::{future::Future, pin::Pin};

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

/// Error returned by an operating-system enforcement backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformError {
    GuardFailed(GuardKind),
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

    /// Closes applications forbidden by the frozen session policy.
    fn close_blocked_apps(&mut self) -> PlatformFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    /// Arms one enforcement guard.
    fn arm_guard(&mut self, guard: GuardKind) -> PlatformFuture<'_, ()>;

    /// Verifies that an armed guard is healthy before the daemon reports Locked.
    fn verify_guard(&mut self, _guard: GuardKind) -> PlatformFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

/// Deterministic backend used by daemon tests without touching the host system.
#[derive(Debug, Default)]
pub struct FakeBackend {
    failing_guards: u8,
}

impl FakeBackend {
    /// Configures one guard to fail when it is armed.
    pub const fn fail_guard(&mut self, guard: GuardKind) {
        self.failing_guards |= guard.bit();
    }

    const fn should_fail(&self, guard: GuardKind) -> bool {
        self.failing_guards & guard.bit() != 0
    }
}

impl PlatformBackend for FakeBackend {
    fn arm_guard(&mut self, guard: GuardKind) -> PlatformFuture<'_, ()> {
        let should_fail = self.should_fail(guard);
        Box::pin(async move {
            if should_fail {
                Err(PlatformError::GuardFailed(guard))
            } else {
                Ok(())
            }
        })
    }
}
