use std::net::Ipv4Addr;

use focus_linux::{EgressProtocol, EgressRuleError, Ipv4EgressRule};

#[test]
fn daemon_rule_encoding_is_stable_and_protocol_aware() {
    let tcp = Ipv4EgressRule::new(Ipv4Addr::new(127, 0, 0, 1), 8080, EgressProtocol::Tcp).unwrap();
    let udp = Ipv4EgressRule::new(Ipv4Addr::new(127, 0, 0, 1), 8080, EgressProtocol::Udp).unwrap();
    let other_port =
        Ipv4EgressRule::new(Ipv4Addr::new(127, 0, 0, 1), 8081, EgressProtocol::Tcp).unwrap();

    assert_eq!(tcp.protocol_number(), 6);
    assert_eq!(udp.protocol_number(), 17);
    assert_eq!(tcp.map_key(), 0x7f00_0001_1f90_0006);
    assert_ne!(tcp.map_key(), udp.map_key());
    assert_ne!(tcp.map_key(), other_port.map_key());
}

#[test]
fn zero_destination_port_is_rejected_before_map_generation() {
    assert_eq!(
        Ipv4EgressRule::new(Ipv4Addr::LOCALHOST, 0, EgressProtocol::Tcp),
        Err(EgressRuleError::InvalidPort)
    );
}
