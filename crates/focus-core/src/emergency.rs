//! Emergency unlock domain state.

use sha2::{Digest, Sha256};

/// Mandatory delay before an emergency unlock can be authorized.
pub const EMERGENCY_DELAY_SECONDS: u64 = 600;

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
}

/// Decision returned when evaluating a pending emergency unlock request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyDecision {
    Waiting { remaining_seconds: u64 },
    InvalidCode,
    Authorized,
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
}

impl EmergencyRequest {
    /// Creates a pending emergency unlock request.
    ///
    /// # Errors
    ///
    /// Returns [`EmergencyError::EmptyReason`] when the supplied reason contains no
    /// non-whitespace characters.
    pub fn new(
        reason: &str,
        requested_at: u64,
        recovery_code: &str,
    ) -> Result<Self, EmergencyError> {
        Self::restore(
            reason.to_owned(),
            requested_at,
            RecoveryCodeHash::from_code(recovery_code),
        )
    }

    /// Restores a previously persisted emergency unlock request.
    ///
    /// # Errors
    ///
    /// Returns [`EmergencyError::EmptyReason`] when the persisted reason contains no
    /// non-whitespace characters.
    pub fn restore(
        reason: String,
        requested_at: u64,
        code_hash: RecoveryCodeHash,
    ) -> Result<Self, EmergencyError> {
        if reason.trim().is_empty() {
            return Err(EmergencyError::EmptyReason);
        }

        Ok(Self {
            reason,
            requested_at,
            code_hash,
        })
    }

    /// Returns the persisted reason for the emergency request.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Returns the absolute request timestamp in Unix seconds.
    #[must_use]
    pub const fn requested_at(&self) -> u64 {
        self.requested_at
    }

    /// Returns the persisted recovery-code fingerprint.
    #[must_use]
    pub const fn code_hash(&self) -> RecoveryCodeHash {
        self.code_hash
    }

    /// Evaluates the request against the current absolute Unix timestamp.
    #[must_use]
    pub fn evaluate(&self, now: u64, recovery_code: &str) -> EmergencyDecision {
        let deadline = self.requested_at.saturating_add(EMERGENCY_DELAY_SECONDS);

        if now < deadline {
            return EmergencyDecision::Waiting {
                remaining_seconds: deadline - now,
            };
        }

        if RecoveryCodeHash::from_code(recovery_code) != self.code_hash {
            return EmergencyDecision::InvalidCode;
        }

        EmergencyDecision::Authorized
    }
}
