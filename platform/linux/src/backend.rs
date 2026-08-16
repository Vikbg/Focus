use focus_platform::{GuardKind, PlatformBackend, PlatformError, PlatformFuture};

use crate::{HostSystemProbe, SystemProbe, evaluate_preflight, require_strict_preflight};

/// Linux platform backend that owns strict preflight while later guards remain fail-closed.
#[derive(Debug)]
pub struct LinuxBackend<P = HostSystemProbe> {
    probe: P,
}

impl Default for LinuxBackend<HostSystemProbe> {
    fn default() -> Self {
        Self {
            probe: HostSystemProbe,
        }
    }
}

impl<P> LinuxBackend<P> {
    /// Creates a Linux backend with an explicit read-only system probe.
    #[must_use]
    pub const fn with_probe(probe: P) -> Self {
        Self { probe }
    }
}

impl<P: SystemProbe> PlatformBackend for LinuxBackend<P> {
    fn preflight(&mut self) -> PlatformFuture<'_, ()> {
        let result = evaluate_preflight(&self.probe)
            .and_then(|report| require_strict_preflight(&report))
            .map_err(|_| PlatformError::PreflightFailed);
        Box::pin(async move { result })
    }

    fn arm_guard(&mut self, guard: GuardKind) -> PlatformFuture<'_, ()> {
        Box::pin(async move { Err(PlatformError::GuardFailed(guard)) })
    }
}
