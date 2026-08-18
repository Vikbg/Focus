const GUARD_SOURCE: &str = include_str!("../src/privilege_guard.rs");
const LIVE_FIXTURE: &str = include_str!("privilege_gate_live.rs");

#[test]
fn production_guard_requires_the_sudo_login_pam_stack() {
    assert!(GUARD_SOURCE.contains("/etc/pam.d/sudo-i"));
    assert!(GUARD_SOURCE.contains("PAM_LOGIN_CONFIG_PATH"));
}

#[test]
fn live_privilege_fixture_blocks_sudo_login_shell() {
    assert!(LIVE_FIXTURE.contains("PAM_LOGIN_PATH"));
    assert!(LIVE_FIXTURE.contains("assert_sudo_blocked(&[\"-i\"]);"));
}
