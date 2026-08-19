use std::net::{IpAddr, Ipv4Addr};

use focus_core::PolicyVersion;
use focus_linux::{DnsPolicyState, DnsResolutionEntry};

fn ipv4(last_octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, last_octet))
}

#[test]
fn ttl_expiration_removes_stale_allow_state() {
    let address = ipv4(10);
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

#[test]
fn stale_policy_version_never_contributes_allow_state() {
    let address = ipv4(20);
    let old_version = PolicyVersion(7);
    let current_version = PolicyVersion(8);
    let mut state = DnsPolicyState::default();

    state.replace_resolution(DnsResolutionEntry::new(
        "physics.example",
        vec![address],
        300,
        old_version,
    ));

    assert!(state.allowed_addresses(299, old_version).contains(&address));
    assert!(state.allowed_addresses(299, current_version).is_empty());
}

#[test]
fn equivalent_dns_names_replace_previous_resolution() {
    let stale_address = ipv4(30);
    let current_address = ipv4(31);
    let version = PolicyVersion(9);
    let mut state = DnsPolicyState::default();

    state.replace_resolution(DnsResolutionEntry::new(
        "Math.Example.",
        vec![stale_address],
        400,
        version,
    ));
    state.replace_resolution(DnsResolutionEntry::new(
        "math.example",
        vec![current_address],
        400,
        version,
    ));

    let allowed = state.allowed_addresses(399, version);
    assert!(!allowed.contains(&stale_address));
    assert!(allowed.contains(&current_address));
}
