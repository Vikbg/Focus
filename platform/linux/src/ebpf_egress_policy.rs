use std::{error::Error, fmt, net::Ipv4Addr};

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
