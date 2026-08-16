//! Focus profile identity, versioning, and immutable session snapshots.

use sha2::{Digest, Sha256};

use crate::{BlockReason, Decision, PolicySet};

/// Current canonical encoding version for frozen session policy snapshots.
pub const SESSION_POLICY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProfileId(pub u128);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersion(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPolicySnapshotError {
    UnsupportedSchemaVersion(u32),
    MalformedPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    id: ProfileId,
    version: PolicyVersion,
    policy: PolicySet,
}

impl Profile {
    #[must_use]
    pub const fn new(id: ProfileId, version: PolicyVersion, policy: PolicySet) -> Self {
        Self {
            id,
            version,
            policy,
        }
    }

    #[must_use]
    pub const fn version(&self) -> PolicyVersion {
        self.version
    }

    #[must_use]
    pub const fn policy(&self) -> PolicySet {
        self.policy
    }

    #[must_use]
    pub const fn snapshot(&self) -> SessionPolicySnapshot {
        SessionPolicySnapshot {
            profile_id: self.id,
            profile_version: self.version,
            policy: self.policy,
        }
    }

    #[must_use]
    pub const fn with_policy(mut self, version: PolicyVersion, policy: PolicySet) -> Self {
        self.version = version;
        self.policy = policy;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPolicySnapshot {
    profile_id: ProfileId,
    profile_version: PolicyVersion,
    policy: PolicySet,
}

impl SessionPolicySnapshot {
    #[must_use]
    pub const fn profile_id(&self) -> ProfileId {
        self.profile_id
    }

    #[must_use]
    pub const fn profile_version(&self) -> PolicyVersion {
        self.profile_version
    }

    #[must_use]
    pub const fn policy(&self) -> PolicySet {
        self.policy
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        SESSION_POLICY_SCHEMA_VERSION
    }

    /// Returns the deterministic payload persisted for this policy snapshot.
    #[must_use]
    pub const fn policy_payload(&self) -> [u8; 1] {
        [encode_decision(self.policy.default_decision())]
    }

    /// Returns a digest covering the profile identity, policy version, schema, and payload.
    #[must_use]
    pub fn policy_sha256(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.profile_id.0.to_be_bytes());
        hasher.update(self.profile_version.0.to_be_bytes());
        hasher.update(SESSION_POLICY_SCHEMA_VERSION.to_be_bytes());
        hasher.update(self.policy_payload());
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        bytes
    }

    /// Restores one canonical frozen policy snapshot from protected storage.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema version or malformed policy payload.
    pub fn restore(
        profile_id: ProfileId,
        profile_version: PolicyVersion,
        schema_version: u32,
        payload: &[u8],
    ) -> Result<Self, SessionPolicySnapshotError> {
        if schema_version != SESSION_POLICY_SCHEMA_VERSION {
            return Err(SessionPolicySnapshotError::UnsupportedSchemaVersion(
                schema_version,
            ));
        }
        let [decision] = payload else {
            return Err(SessionPolicySnapshotError::MalformedPolicy);
        };
        let policy = PolicySet::new(decode_decision(*decision)?);
        Ok(Self {
            profile_id,
            profile_version,
            policy,
        })
    }
}

const fn encode_decision(decision: Decision) -> u8 {
    match decision {
        Decision::Allow => 0,
        Decision::Block(BlockReason::SecurityInvariant) => 1,
        Decision::Block(BlockReason::SessionRestriction) => 2,
        Decision::Block(BlockReason::ExplicitBlock) => 3,
        Decision::Block(BlockReason::Unknown) => 4,
        Decision::Classify => 5,
        Decision::FailClosed(BlockReason::SecurityInvariant) => 6,
        Decision::FailClosed(BlockReason::SessionRestriction) => 7,
        Decision::FailClosed(BlockReason::ExplicitBlock) => 8,
        Decision::FailClosed(BlockReason::Unknown) => 9,
    }
}

const fn decode_decision(value: u8) -> Result<Decision, SessionPolicySnapshotError> {
    match value {
        0 => Ok(Decision::Allow),
        1 => Ok(Decision::Block(BlockReason::SecurityInvariant)),
        2 => Ok(Decision::Block(BlockReason::SessionRestriction)),
        3 => Ok(Decision::Block(BlockReason::ExplicitBlock)),
        4 => Ok(Decision::Block(BlockReason::Unknown)),
        5 => Ok(Decision::Classify),
        6 => Ok(Decision::FailClosed(BlockReason::SecurityInvariant)),
        7 => Ok(Decision::FailClosed(BlockReason::SessionRestriction)),
        8 => Ok(Decision::FailClosed(BlockReason::ExplicitBlock)),
        9 => Ok(Decision::FailClosed(BlockReason::Unknown)),
        _ => Err(SessionPolicySnapshotError::MalformedPolicy),
    }
}
