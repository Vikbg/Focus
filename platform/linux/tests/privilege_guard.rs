use focus_linux::{PrivilegeGuardControl, ProductionPrivilegeGuard};

fn assert_privilege_control<T: PrivilegeGuardControl>() {}

#[test]
fn production_privilege_guard_is_scoped_to_the_protected_uid() {
    assert_privilege_control::<ProductionPrivilegeGuard>();
    let guard = ProductionPrivilegeGuard::for_uid(1000);

    assert_eq!(guard.enforced_uid(), 1000);
}

#[test]
fn production_privilege_guard_requires_fail_closed_pam_account_rule() {
    let guard = ProductionPrivilegeGuard::for_uid(1000);

    assert_eq!(
        guard.required_pam_account_rule(),
        "account requisite pam_listfile.so item=user sense=deny file=/var/lib/focus/privilege-deny-users onerr=fail"
    );
}
