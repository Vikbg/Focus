/// Deterministic Focus-owned systemd unit name for one approved OpenVPN profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVpnUnitName(String);

impl OpenVpnUnitName {
    /// Derives the only valid OpenVPN unit identity from the stable Focus VPN id.
    #[must_use]
    pub fn from_id(id: u128) -> Self {
        Self(format!("focus-openvpn-{id}.service"))
    }

    /// Returns the fixed systemd unit name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
