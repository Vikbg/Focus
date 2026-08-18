const LIVE_FIXTURE: &str = include_str!("privilege_gate_live.rs");

#[test]
fn live_privilege_fixture_exercises_a_cached_sudo_ticket() {
    assert!(LIVE_FIXTURE.contains("timestamp_type=global"));
    assert!(LIVE_FIXTURE.contains("sudo\", \"-S\", \"-v"));
    assert!(LIVE_FIXTURE.contains("chpasswd"));
    assert!(!LIVE_FIXTURE.contains("NOPASSWD"));
}

#[test]
fn live_privilege_fixture_uses_a_non_escalating_typed_broker_action() {
    assert!(LIVE_FIXTURE.contains("PrivilegedAction::DockerStop"));
    assert!(!LIVE_FIXTURE.contains(
        "execute_privileged_action(PrivilegedAction::DockerStart)"
    ));
}
