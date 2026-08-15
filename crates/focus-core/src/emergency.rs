//! Emergency unlock domain state.

use sha2::{Digest, Sha256};

/// Mandatory delay before an emergency unlock can be authorized.
pub const EMERGENCY_DELAY_SECONDS: u64 = 600;

/// Allowed wall-clock drift before Focus records an anomaly.
pub const WALL_CLOCK_DRIFT_TOLERANCE_SECONDS: u64 = 5;

/// Stable identifier for one operating-system boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BootId(pub u128);

/// One trusted clock observation supplied by the platform layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmergencyClockSample {
    boot_id: BootId,
    monotonic_seconds: u64,
    unix_seconds: u64,
}

impl EmergencyClockSample {
    /// Creates one clock observation.
    #[must_use]
    pub const fn new(boot_id: BootId, monotonic_seconds: u64, unix_seconds: u64) -> Self {
        Self {
            boot_id,
            monotonic_seconds,
            unix_seconds,
        }
    }

    /// Returns the boot identifier attached to this observation.
    #[must_use]
    pub const fn boot_id(self) -> BootId {
        self.boot_id
    }

    /// Returns monotonic seconds elapsed within the current boot.
    #[must_use]
    pub const fn monotonic_seconds(self) -> u64 {
        self.monotonic_seconds
    }

    /// Returns the wall-clock Unix timestamp used only for audit and anomaly detection.
    #[must_use]
    pub const fn unix_seconds(self) -> u64 {
        self.unix_seconds
    }
}

/// Persistent timing evidence for an emergency request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmergencyTimingState {
    boot_id: BootId,
    monotonic_anchor_seconds: u64,
    unix_anchor_seconds: u64,
    verified_elapsed_seconds: u64,
}

impl EmergencyTimingState {
    /// Restores persisted timing evidence.
    ///
    /// # Errors
    ///
    /// Returns [`EmergencyError::InvalidTimingState`] when verified elapsed time exceeds
    /// the mandatory emergency delay.
    pub const fn restore(
        boot_id: BootId,
        monotonic_anchor_seconds: u64,
        unix_anchor_seconds: u64,
        verified_elapsed_seconds: u64,
    ) -> Result<Self, EmergencyError> {
        if verified_elapsed_seconds > EMERGENCY_DELAY_SECONDS {
            return Err(EmergencyError::InvalidTimingState);
        }

        Ok(Self {
            boot_id,
            monotonic_anchor_seconds,
            unix_anchor_seconds,
            verified_elapsed_seconds,
        })
    }

    /// Returns the boot identifier associated with the latest verified anchor.
    #[must_use]
    pub const fn boot_id(self) -> BootId {
        self.boot_id
    }

    /// Returns the latest verified monotonic anchor.
    #[must_use]
    pub const fn monotonic_anchor_seconds(self) -> u64 {
        self.monotonic_anchor_seconds
    }

    /// Returns the wall-clock value observed at the latest verified anchor.
    #[must_use]
    pub const fn unix_anchor_seconds(self) -> u64 {
        self.unix_anchor_seconds
    }

    /// Returns elapsed seconds proven by monotonic observations.
    #[must_use]
    pub const fn verified_elapsed_seconds(self) -> u64 {
        self.verified_elapsed_seconds
    }
}

/// Persistent emergency unlock state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyState {
    Inactive,
    Pending,
    Authorized,
}

/// Error returned while constructing or restoring an emergency unlock request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyError {
    EmptyReason,
    EmptyRecoveryCode,
    InvalidTimingState,
}

/// Clock-integrity observation produced while evaluating an emergency request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyClockEvent {
    None,
    WallClockAnomaly,
    RebootDetected,
    MonotonicRegression,
}

/// Decision returned when evaluating a pending emergency unlock request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyDecision {
    Waiting { remaining_seconds: u64 },
    InvalidCode,
    ClockIntegrityFailure,
    Authorized,
}

/// Combined policy decision and clock-integrity event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmergencyEvaluation {
    decision: EmergencyDecision,
    clock_event: EmergencyClockEvent,
}

impl EmergencyEvaluation {
    const fn new(decision: EmergencyDecision, clock_event: EmergencyClockEvent) -> Self {
        Self {
            decision,
            clock_event,
        }
    }

    /// Returns the emergency-unlock policy decision.
    #[must_use]
    pub const fn decision(self) -> EmergencyDecision {
        self.decision
    }

    /// Returns the clock-integrity event detected during this observation.
    #[must_use]
    pub const fn clock_event(self) -> EmergencyClockEvent {
        self.clock_event
    }
}

/// SHA-256 fingerprint of a recovery code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryCodeHash([u8; 32]);

impl RecoveryCodeHash {
    /// Derives a recovery-code fingerprint without retaining the plaintext code.
    #[must_use]
    pub fn from_code(code: &str) -> Self {
        let digest = Sha256::digest(code.as_bytes());
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    /// Restores a fingerprint from its fixed-width persisted representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-width persisted representation of this fingerprint.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Persistent emergency unlock request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyRequest {
    reason: String,
    requested_at: u64,
    code_hash: RecoveryCodeHash,
    timing: EmergencyTimingState,
}

impl EmergencyRequest {
    /// Creates a pending emergency unlock request from an initial clock observation.
    ///
    /// # Errors
    ///
    /// Returns [`EmergencyError::EmptyReason`] when the supplied reason contains no
    /// non-whitespace characters, or [`EmergencyError::EmptyRecoveryCode`] when the
    /// supplied recovery code contains no non-whitespace characters.
    pub fn new(
        reason: &str,
        clock: EmergencyClockSample,
        recovery_code: &str,
    ) -> Result<Self, EmergencyError> {
        if recovery_code.trim().is_empty() {
            return Err(EmergencyError::EmptyRecoveryCode);
        }

        let timing = EmergencyTimingState {
            boot_id: clock.boot_id,
            monotonic_anchor_seconds: clock.monotonic_seconds,
            unix_anchor_seconds: clock.unix_seconds,
            verified_elapsed_seconds: 0,
        };

        Self::restore(
            reason.to_owned(),
            clock.unix_seconds,
            RecoveryCodeHash::from_code(recovery_code),
            timing,
        )
    }

    /// Restores a previously persisted emergency unlock request.
    ///
    /// # Errors
    ///
    /// Returns [`EmergencyError::EmptyReason`] when the persisted reason contains no
    /// non-whitespace characters, or [`EmergencyError::InvalidTimingState`] when the
    /// persisted timing evidence is invalid.
    pub fn restore(
        reason: String,
        requested_at: u64,
        code_hash: RecoveryCodeHash,
        timing: EmergencyTimingState,
    ) -> Result<Self, EmergencyError> {
        if reason.trim().is_empty() {
            return Err(EmergencyError::EmptyReason);
        }
        if timing.verified_elapsed_seconds > EMERGENCY_DELAY_SECONDS {
            return Err(EmergencyError::InvalidTimingState);
        }

        Ok(Self {
            reason,
            requested_at,
            code_hash,
            timing,
        })
    }

    /// Returns the persisted reason for the emergency request.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Returns the request wall-clock timestamp for audit purposes.
    #[must_use]
    pub const fn requested_at(&self) -> u64 {
        self.requested_at
    }

    /// Returns the persisted recovery-code fingerprint.
    #[must_use]
    pub const fn code_hash(&self) -> RecoveryCodeHash {
        self.code_hash
    }

    /// Returns persistent monotonic timing evidence.
    #[must_use]
    pub const fn timing_state(&self) -> EmergencyTimingState {
        self.timing
    }

    /// Evaluates a new clock observation without trusting wall-clock time for elapsed delay.
    #[must_use]
    pub fn evaluate(
        &mut self,
        clock: EmergencyClockSample,
        recovery_code: &str,
    ) -> EmergencyEvaluation {
        let clock_event = if clock.boot_id != self.timing.boot_id {
            self.timing.boot_id = clock.boot_id;
            self.timing.monotonic_anchor_seconds = clock.monotonic_seconds;
            self.timing.unix_anchor_seconds = clock.unix_seconds;
            EmergencyClockEvent::RebootDetected
        } else {
            if clock.monotonic_seconds < self.timing.monotonic_anchor_seconds {
                return EmergencyEvaluation::new(
                    EmergencyDecision::ClockIntegrityFailure,
                    EmergencyClockEvent::MonotonicRegression,
                );
            }

            let monotonic_delta = clock
                .monotonic_seconds
                .saturating_sub(self.timing.monotonic_anchor_seconds);
            self.timing.verified_elapsed_seconds = self
                .timing
                .verified_elapsed_seconds
                .saturating_add(monotonic_delta)
                .min(EMERGENCY_DELAY_SECONDS);

            let expected_unix = self
                .timing
                .unix_anchor_seconds
                .saturating_add(monotonic_delta);
            let drift = clock.unix_seconds.abs_diff(expected_unix);

            self.timing.monotonic_anchor_seconds = clock.monotonic_seconds;
            self.timing.unix_anchor_seconds = clock.unix_seconds;

            if drift > WALL_CLOCK_DRIFT_TOLERANCE_SECONDS {
                EmergencyClockEvent::WallClockAnomaly
            } else {
                EmergencyClockEvent::None
            }
        };

        let remaining_seconds = EMERGENCY_DELAY_SECONDS
            .saturating_sub(self.timing.verified_elapsed_seconds);
        if remaining_seconds != 0 {
            return EmergencyEvaluation::new(
                EmergencyDecision::Waiting { remaining_seconds },
                clock_event,
            );
        }

        if RecoveryCodeHash::from_code(recovery_code) != self.code_hash {
            return EmergencyEvaluation::new(EmergencyDecision::InvalidCode, clock_event);
        }

        EmergencyEvaluation::new(EmergencyDecision::Authorized, clock_event)
    }
}
