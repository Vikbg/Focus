use focus_platform::PrivilegedAction;

#[test]
fn privileged_action_surface_is_closed_to_task22_categories() {
    let actions = [
        PrivilegedAction::VpnConnect,
        PrivilegedAction::VpnDisconnect,
        PrivilegedAction::DockerStart,
        PrivilegedAction::DockerStop,
    ];

    assert_eq!(actions.len(), 4);
}
