//! Emergency unlock domain state.

use sha2::{Digest, Sha256};

use crate::SessionId;

/// Mandatory delay before an emergency unlock can be authorized.
pub const EMERGENCY_DELAY_SECONDS: u64 = 600;

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const EMERGENCY_DELAY_NANOS: u64 = EMERGENCY_DELAY_SECONDS * NANOS_PER_SECOND;

/// Allowed wall-clock drift before Focus records an anomaly.
pub const WALL_CLOCK_DRIFT_TOLERANCE_SECONDS: u64 = 5;

/// Stable identifier for one operating-system boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BootId(pub u128);

/// One trusted clock observation supplied by the platform layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmergencyClockSample {
    boot_id: BootId,
    monotonic_nanos: u64,
    unix_seconds: u64,
}

impl EmergencyClockSample {
    /// Creates one clock observation from whole monotonic seconds.
    #[must_use]
    pub const fn new(boot_id: BootId, monotonic_seconds: u64, unix_seconds: u64) -> Self {
        Self::new_nanos(
            boot_id,
            monotonic_seconds.saturating_mul(NANOS_PER_SECOND),
            unix_seconds,
        )
    }

    /// Creates one clock observation from monotonic nanoseconds.
    #[must_use]
    pub const fn new_nanos(boot_id: BootId, monotonic_nanos: u64, unix_seconds: u64) -> Self {
        Self {
            boot_id,
            monotonic_nanos,
            unix_seconds,
        }
    }

    /// Returns the boot identifier attached to this observation.
    #[must_use]
    pub const fn boot_id(self) -> BootId {
        self.boot_id
    }

    /// Returns whole monotonic seconds elapsed within the current boot.
    #[must_use]
    pub const fn monotonic_seconds(self) -> u64 {
        self.monotonic_nanos / NANOS_PER_SECOND
    }

    /// Returns monotonic nanoseconds elapsed within the current boot.
    #[must_use]
    pub const fn monotonic_nanos(self) -> u64 {
        self.monotonic_nanos
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
    monotonic_anchor_nanos: u64,
    unix_anchor_seconds: u64,
    verified_elapsed_nanos: u64,
}

impl EmergencyTimingState {
    /// Restores persisted timing evidence encoded in whole seconds.
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
        Self::restore_nanos(
            boot_id,
            monotonic_anchor_seconds.saturating_mul(NANOS_PER_SECOND),
            unix_anchor_seconds,
            verified_elapsed_seconds.saturating_mul(NANOS_PER_SECOND),
        )
    }

    /// Restores persisted timing evidence encoded in nanoseconds.
    ///
    /// # Errors
    ///
    /// Returns [`EmergencyError::InvalidTimingState`] when verified elapsed time exceeds
    /// the mandatory emergency delay.
    pub const fn restore_nanos(
        boot_id: BootId,
        monotonic_anchor_nanos: u64,
        unix_anchor_seconds: u64,
        verified_elapsed_nanos: u64,
    ) -> Result<Self, EmergencyError> {
        if verified_elapsed_nanos > EMERGENCY_DELAY_NANOS {
            return Err(EmergencyError::InvalidTimingState);
        }

        Ok(Self {
            boot_id,
            monotonic_anchor_nanos,
            unix_anchor_seconds,
            verified_elapsed_nanos,
        })
    }

    /// Returns the boot identifier associated with the latest verified anchor.
    #[must_use]
    pub const fn boot_id(self) -> BootId {
        self.boot_id
    }

    /// Returns the latest verified monotonic anchor in whole seconds.
    #[must_use]
    pub const fn monotonic_anchor_seconds(self) -> u64 {
        self.monotonic_anchor_nanos / NANOS_PER_SECOND
    }

    /// Returns the latest verified monotonic anchor in nanoseconds.
    #[must_use]
    pub const fn monotonic_anchor_nanos(self) -> u64 {
        self.monotonic_anchor_nanos
    }

    /// Returns the wall-clock value observed at the latest verified anchor.
    #[must_use]
    pub const fn unix_anchor_seconds(self) -> u64 {
        self.unix_anchor_seconds
    }

    /// Returns elapsed whole seconds proven by monotonic observations.
    #[must_use]
    pub const fn verified_elapsed_seconds(self) -> u64 {
        self.verified_elapsed_nanos / NANOS_PER_SECOND
    }

    /// Returns elapsed nanoseconds proven by monotonic observations.
    #[must_use]
    pub const fn verified_elapsed_nanos(self) -> u64 {
        self.verified_elapsed_nanos
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

    /// Compares a candidate recovery code with this precommitted fingerprint.
    #[must_use]
    pub fn matches(self, candidate: &str) -> bool {
        let candidate = Self::from_code(candidate);
        let mut difference = 0_u8;
        for index in 0..self.0.len() {
            difference |= self.0[index] ^ candidate.0[index];
        }
        difference == 0
    }
}

/// Persistent emergency unlock request bound to one active session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyRequest {
    session_id: SessionId,
    reason: String,
    requested_at: u64,
    timing: EmergencyTimingState,
}

impl EmergencyRequest {
    /// Creates a pending emergency unlock request from an initial clock observation.
    ///
    /// The recovery secret is intentionally not accepted here. Its fingerprint must already
    /// be frozen in the active session before the session reaches `Locked`.
    ///
    /// # Errors
    ///
    /// Returns [`EmergencyError::EmptyReason`] when the supplied reason contains no
    /// non-whitespace characters.
    pub fn new(
        session_id: SessionId,
        reason: &str,
        clock: EmergencyClockSample,
    ) -> Result<Self, EmergencyError> {
        let timing = EmergencyTimingState {
            boot_id: clock.boot_id,
            monotonic_anchor_nanos: clock.monotonic_nanos,
            unix_anchor_seconds: clock.unix_seconds,
            verified_elapsed_nanos: 0,
        };

        Self::restore(session_id, reason.to_owned(), clock.unix_seconds, timing)
    }

    /// Restores a previously persisted emergency unlock request.
    ///
    /// # Errors
    ///
    /// Returns [`EmergencyError::EmptyReason`] when the persisted reason contains no
    /// non-whitespace characters, or [`EmergencyError::InvalidTimingState`] when the
    /// persisted timing evidence is invalid.
    pub fn restore(
        session_id: SessionId,
        reason: String,
        requested_at: u64,
        timing: EmergencyTimingState,
    ) -> Result<Self, EmergencyError> {
        if reason.trim().is_empty() {
            return Err(EmergencyError::EmptyReason);
        }
        if timing.verified_elapsed_nanos > EMERGENCY_DELAY_NANOS {
            return Err(EmergencyError::InvalidTimingState);
        }

        Ok(Self {
            session_id,
            reason,
            requested_at,
            timing,
        })
    }

    /// Returns the active session to which this request is bound.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
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

    /// Returns persistent monotonic timing evidence.
    #[must_use]
    pub const fn timing_state(&self) -> EmergencyTimingState {
        self.timing
    }

    /// Evaluates a new clock observation against the recovery hash frozen before lock.
    #[must_use]
    pub fn evaluate(
        &mut self,
        clock: EmergencyClockSample,
        expected_code_hash: RecoveryCodeHash,
        recovery_code: &str,
    ) -> EmergencyEvaluation {
        let clock_event = if clock.boot_id == self.timing.boot_id {
            if clock.monotonic_nanos < self.timing.monotonic_anchor_nanos {
                return EmergencyEvaluation::new(
                    EmergencyDecision::ClockIntegrityFailure,
                    EmergencyClockEvent::MonotonicRegression,
                );
            }

            let monotonic_delta_nanos = clock
                .monotonic_nanos
                .saturating_sub(self.timing.monotonic_anchor_nanos);
            self.timing.verified_elapsed_nanos = self
                .timing
                .verified_elapsed_nanos
                .saturating_add(monotonic_delta_nanos)
                .min(EMERGENCY_DELAY_NANOS);

            let expected_unix = self
                .timing
                .unix_anchor_seconds
                .saturating_add(monotonic_delta_nanos / NANOS_PER_SECOND);
            let drift = clock.unix_seconds.abs_diff(expected_unix);

            self.timing.monotonic_anchor_nanos = clock.monotonic_nanos;
            self.timing.unix_anchor_seconds = clock.unix_seconds;

            if drift > WALL_CLOCK_DRIFT_TOLERANCE_SECONDS {
                EmergencyClockEvent::WallClockAnomaly
            } else {
                EmergencyClockEvent::None
            }
        } else {
            self.timing.boot_id = clock.boot_id;
            self.timing.monotonic_anchor_nanos = clock.monotonic_nanos;
            self.timing.unix_anchor_seconds = clock.unix_seconds;
            EmergencyClockEvent::RebootDetected
        };

        let remaining_nanos =
            EMERGENCY_DELAY_NANOS.saturating_sub(self.timing.verified_elapsed_nanos);
        if remaining_nanos != 0 {
            return EmergencyEvaluation::new(
                EmergencyDecision::Waiting {
                    remaining_seconds: remaining_nanos.div_ceil(NANOS_PER_SECOND),
                },
                clock_event,
            );
        }

        if !expected_code_hash.matches(recovery_code) {
            return EmergencyEvaluation::new(EmergencyDecision::InvalidCode, clock_event);
        }

        EmergencyEvaluation::new(EmergencyDecision::Authorized, clock_event)
    }
}
