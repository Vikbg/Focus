from pathlib import Path

path = Path("bins/focusd/src/lib.rs")
text = path.read_text()

replacements = [
    (
        """pub enum ArmError {
    ActiveSessionExists,
    Store(StoreError),
    Transition(TransitionError),
    Platform(PlatformError),
}""",
        """pub enum ArmError {
    ActiveSessionExists,
    Store(StoreError),
    Transition(TransitionError),
    Platform(PlatformError),
    ArmingFailed {
        source: PlatformError,
        compensation: CompensationReport,
    },
}""",
    ),
    (
        """            Self::Platform(error) => write!(formatter, \"platform enforcement error: {error:?}\"),
""",
        """            Self::Platform(error) => write!(formatter, \"platform enforcement error: {error:?}\"),
            Self::ArmingFailed { source, .. } => {
                write!(formatter, \"platform enforcement failed during arming: {source:?}\")
            }
""",
    ),
    (
        """            Self::ActiveSessionExists | Self::Transition(_) | Self::Platform(_) => None,
""",
        """            Self::ActiveSessionExists
            | Self::Transition(_)
            | Self::Platform(_)
            | Self::ArmingFailed { .. } => None,
""",
    ),
    (
        """impl From<PlatformError> for ArmError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}
""",
        """impl From<PlatformError> for ArmError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

impl ArmError {
    /// Returns the compensation report for a platform failure that occurred after
    /// the active `Arming` record was persisted.
    #[must_use]
    pub const fn compensation_report(&self) -> Option<&CompensationReport> {
        match self {
            Self::ArmingFailed { compensation, .. } => Some(compensation),
            _ => None,
        }
    }
}
""",
    ),
    (
        """struct ArmingCoordinator<'a, B: PlatformBackend> {
    backend: &'a mut B,
    applied: Vec<GuardKind>,
}

impl<'a, B: PlatformBackend> ArmingCoordinator<'a, B> {
    fn new(backend: &'a mut B) -> Self {
        Self {
            backend,
            applied: Vec::new(),
        }
    }

    async fn close_blocked_apps(&mut self) -> Result<(), PlatformError> {
        self.backend.close_blocked_apps().await
    }

    async fn arm_guard(&mut self, guard: GuardKind) -> Result<(), PlatformError> {
        self.backend.arm_guard(guard).await?;
        self.applied.push(guard);
        Ok(())
    }

    async fn verify_guard(&mut self, guard: GuardKind) -> Result<(), PlatformError> {
        self.backend.verify_guard(guard).await
    }

    async fn compensate(&mut self) {
        for guard in self.applied.iter().rev().copied() {
            let _ = self.backend.disarm_guard(guard).await;
        }
    }
}
""",
        """/// Result of one best-effort rollback of platform guards applied during arming.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompensationReport {
    remaining_guards: Vec<GuardKind>,
}

impl CompensationReport {
    /// Returns guards whose removal failed and may therefore still be active.
    #[must_use]
    pub fn remaining_guards(&self) -> &[GuardKind] {
        &self.remaining_guards
    }
}

/// Orders platform guard application and tracks effects that require compensation.
pub struct ArmingCoordinator<'a, B: PlatformBackend> {
    backend: &'a mut B,
    applied: Vec<GuardKind>,
}

impl<'a, B: PlatformBackend> ArmingCoordinator<'a, B> {
    /// Creates an empty arming ledger for one platform backend.
    pub fn new(backend: &'a mut B) -> Self {
        Self {
            backend,
            applied: Vec::new(),
        }
    }

    async fn close_blocked_apps(&mut self) -> Result<(), PlatformError> {
        self.backend.close_blocked_apps().await
    }

    /// Arms one guard and records it only after the platform operation succeeds.
    ///
    /// # Errors
    ///
    /// Returns the platform error without adding the failed guard to the applied ledger.
    pub async fn arm_guard(&mut self, guard: GuardKind) -> Result<(), PlatformError> {
        self.backend.arm_guard(guard).await?;
        self.applied.push(guard);
        Ok(())
    }

    async fn verify_guard(&mut self, guard: GuardKind) -> Result<(), PlatformError> {
        self.backend.verify_guard(guard).await
    }

    /// Reverses applied guards in reverse order without double-disarming successes.
    ///
    /// Failed disarms remain in the ledger so a later retry can safely attempt them again.
    pub async fn compensate(&mut self) -> CompensationReport {
        let mut remaining = Vec::new();
        while let Some(guard) = self.applied.pop() {
            if self.backend.disarm_guard(guard).await.is_err() {
                remaining.push(guard);
            }
        }
        remaining.reverse();
        self.applied.extend(remaining.iter().copied());
        CompensationReport {
            remaining_guards: remaining,
        }
    }
}
""",
    ),
    (
        """    coordinator.compensate().await;
    let failure = SessionMachine::apply(
""",
        """    let compensation = coordinator.compensate().await;
    let failure = SessionMachine::apply(
""",
    ),
    (
        """    store.persist_transition(session.id(), &failure)?;
    Err(ArmError::Platform(platform_error))
}""",
        """    store.persist_transition(session.id(), &failure)?;
    Err(ArmError::ArmingFailed {
        source: platform_error,
        compensation,
    })
}""",
    ),
]

for old, new in replacements:
    if old not in text:
        raise SystemExit(f"expected coordinator patch fragment not found: {old[:80]!r}")
    text = text.replace(old, new, 1)

path.write_text(text)
