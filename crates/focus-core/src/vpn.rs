//! VPN identity types shared by Focus policy logic.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VpnId(pub u128);
