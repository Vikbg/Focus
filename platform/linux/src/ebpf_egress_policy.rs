use std::{collections::BTreeSet, error::Error, fmt, net::Ipv4Addr};

/// Transport protocols supported by the strict cgroup eBPF egress map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EgressProtocol {
    Tcp,
    Udp,
}

impl EgressProtocol {
    /// Returns the IANA IP protocol number consumed by the eBPF program.
    #[must_use]
    pub const fn protocol_number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

/// Invalid daemon-prepared egress rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressRuleError {
    InvalidPort,
}

impl fmt::Display for EgressRuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPort => formatter.write_str("egress destination port must be nonzero"),
        }
    }
}

impl Error for EgressRuleError {}

/// Error returned while replacing or verifying a strict eBPF allow map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressMapError {
    MutationFailed,
    VerificationFailed,
}

impl fmt::Display for EgressMapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MutationFailed => formatter.write_str("eBPF egress allow map mutation failed"),
            Self::VerificationFailed => {
                formatter.write_str("eBPF egress allow map verification failed")
            }
        }
    }
}

impl Error for EgressMapError {}

/// Narrow authority over the daemon-prepared exact eBPF egress allow map.
pub trait EgressAllowMap {
    /// Removes every existing allow entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the map cannot be cleared safely.
    fn clear(&mut self) -> Result<(), EgressMapError>;

    /// Inserts one exact encoded allow key.
    ///
    /// # Errors
    ///
    /// Returns an error when the entry cannot be inserted safely.
    fn insert(&mut self, key: u64) -> Result<(), EgressMapError>;

    /// Reads back every encoded allow key currently stored in the map.
    ///
    /// # Errors
    ///
    /// Returns an error when exact map contents cannot be observed.
    fn keys(&mut self) -> Result<Vec<u64>, EgressMapError>;
}

/// One exact IPv4 endpoint prepared by the daemon for an eBPF allow map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4EgressRule {
    address: Ipv4Addr,
    port: u16,
    protocol: EgressProtocol,
}

impl Ipv4EgressRule {
    /// Creates one exact allow-map entry.
    ///
    /// # Errors
    ///
    /// Returns [`EgressRuleError::InvalidPort`] when `port` is zero.
    pub const fn new(
        address: Ipv4Addr,
        port: u16,
        protocol: EgressProtocol,
    ) -> Result<Self, EgressRuleError> {
        if port == 0 {
            return Err(EgressRuleError::InvalidPort);
        }
        Ok(Self {
            address,
            port,
            protocol,
        })
    }

    /// Returns the exact IPv4 destination.
    #[must_use]
    pub const fn address(self) -> Ipv4Addr {
        self.address
    }

    /// Returns the exact nonzero destination port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }

    /// Returns the transport protocol number stored in the map key.
    #[must_use]
    pub const fn protocol_number(self) -> u8 {
        self.protocol.protocol_number()
    }

    /// Packs the rule into the architecture-independent key consumed by the eBPF program.
    #[must_use]
    pub fn map_key(self) -> u64 {
        (u64::from(u32::from(self.address)) << 32)
            | (u64::from(self.port) << 16)
            | u64::from(self.protocol_number())
    }
}

/// Replaces the complete eBPF allow map with the exact canonical rule set and verifies read-back.
///
/// Existing entries are cleared before any new allow is inserted. A failed insertion can therefore
/// leave only a subset of the requested allows, which is restrictive rather than permissive. The
/// caller must treat any returned error as protection failure and must not claim the policy is
/// healthy.
///
/// # Errors
///
/// Returns the map mutation error when clearing or inserting fails. Returns
/// [`EgressMapError::VerificationFailed`] when read-back does not exactly match the canonical rule
/// set.
pub fn replace_egress_rules<M: EgressAllowMap>(
    map: &mut M,
    rules: &[Ipv4EgressRule],
) -> Result<(), EgressMapError> {
    let expected: BTreeSet<u64> = rules.iter().map(|rule| rule.map_key()).collect();

    map.clear()?;
    for key in expected.iter().copied() {
        map.insert(key)?;
    }

    let observed: BTreeSet<u64> = map.keys()?.into_iter().collect();
    if observed == expected {
        Ok(())
    } else {
        Err(EgressMapError::VerificationFailed)
    }
}
