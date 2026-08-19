use std::net::{IpAddr, Ipv4Addr};

use focus_core::PolicyVersion;
use focus_linux::{DnsPolicyState, DnsResolutionEntry};

#[test]
fn ttl_expiration_removes_stale_allow_state() {
    let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    let version = PolicyVersion(7);
    let mut state = DnsPolicyState::default();

    state.replace_resolution(DnsResolutionEntry::new(
        "math.example",
        vec![address],
        120,
        version,
    ));

    assert!(state.allowed_addresses(119, version).contains(&address));
    assert!(!state.allowed_addresses(120, version).contains(&address));

    state.prune_expired(120);
    assert!(state.is_empty());
}
