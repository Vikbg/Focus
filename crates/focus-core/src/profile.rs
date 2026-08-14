//! Focus profile identity, versioning, and immutable session snapshots.

use crate::PolicySet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProfileId(pub u128);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersion(pub u64);

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
}
