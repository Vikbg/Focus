use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use focus_core::PolicyVersion;

/// One policy-owned DNS resolution with an absolute expiration time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResolutionEntry {
    domain: String,
    addresses: BTreeSet<IpAddr>,
    expires_at_unix_seconds: u64,
    policy_version: PolicyVersion,
}

impl DnsResolutionEntry {
    /// Creates one complete domain-to-address resolution snapshot.
    #[must_use]
    pub fn new(
        domain: impl Into<String>,
        addresses: impl IntoIterator<Item = IpAddr>,
        expires_at_unix_seconds: u64,
        policy_version: PolicyVersion,
    ) -> Self {
        Self {
            domain: domain.into(),
            addresses: addresses.into_iter().collect(),
            expires_at_unix_seconds,
            policy_version,
        }
    }

    /// Returns the domain represented by this resolution.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the policy version that owns this resolution.
    #[must_use]
    pub const fn policy_version(&self) -> PolicyVersion {
        self.policy_version
    }

    /// Returns the absolute Unix-second expiration boundary.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    fn is_live_at(&self, now_unix_seconds: u64) -> bool {
        now_unix_seconds < self.expires_at_unix_seconds
    }
}

/// Policy-aware DNS resolution state used to derive temporary network allow state.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DnsPolicyState {
    entries: BTreeMap<String, DnsResolutionEntry>,
}

impl DnsPolicyState {
    /// Replaces the complete current resolution for one domain.
    pub fn replace_resolution(&mut self, entry: DnsResolutionEntry) {
        self.entries.insert(entry.domain.clone(), entry);
    }

    /// Returns all currently live addresses owned by exactly one policy version.
    #[must_use]
    pub fn allowed_addresses(
        &self,
        now_unix_seconds: u64,
        policy_version: PolicyVersion,
    ) -> BTreeSet<IpAddr> {
        self.entries
            .values()
            .filter(|entry| {
                entry.policy_version == policy_version && entry.is_live_at(now_unix_seconds)
            })
            .flat_map(|entry| entry.addresses.iter().copied())
            .collect()
    }

    /// Removes entries whose TTL boundary has been reached or passed.
    pub fn prune_expired(&mut self, now_unix_seconds: u64) {
        self.entries
            .retain(|_, entry| entry.is_live_at(now_unix_seconds));
    }

    /// Returns whether no DNS resolution state remains stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
