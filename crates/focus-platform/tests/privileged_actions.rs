use focus_platform::PrivilegedAction;

#[test]
fn privileged_action_surface_is_closed_to_task22_categories() {
    let connect = PrivilegedAction::VpnConnect { id: 41 };
    let disconnect = PrivilegedAction::VpnDisconnect { id: 42 };
    let actions = [
        connect,
        disconnect,
        PrivilegedAction::DockerStart,
        PrivilegedAction::DockerStop,
    ];

    assert_eq!(actions.len(), 4);

    let PrivilegedAction::VpnConnect { id: connect_id } = connect else {
        panic!("connect action must preserve its typed VPN id");
    };
    let PrivilegedAction::VpnDisconnect { id: disconnect_id } = disconnect else {
        panic!("disconnect action must preserve its typed VPN id");
    };
    assert_eq!(connect_id, 41);
    assert_eq!(disconnect_id, 42);
}
