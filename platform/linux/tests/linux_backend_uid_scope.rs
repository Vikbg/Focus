use focus_linux::LinuxBackend;

#[test]
fn production_backend_binds_every_user_scoped_guard_to_the_same_uid() {
    let backend = LinuxBackend::for_uid(1000);

    assert_eq!(backend.process_control().enforced_uid(), Some(1000));
    assert_eq!(backend.process_guard().enforced_uid(), Some(1000));
    assert_eq!(backend.privilege_guard().enforced_uid(), 1000);
}
