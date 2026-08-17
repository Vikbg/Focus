use focus_linux::ProductionPrivilegeGuard;

#[test]
fn production_privilege_guard_is_scoped_to_the_protected_uid() {
    let guard = ProductionPrivilegeGuard::for_uid(1000);

    assert_eq!(guard.enforced_uid(), 1000);
}
