use focus_linux::LinuxBackend;

#[test]
fn production_backend_binds_process_control_and_guard_to_the_same_uid() {
    let backend = LinuxBackend::for_uid(1000);

    assert_eq!(backend.process_control().enforced_uid(), Some(1000));
    assert_eq!(backend.process_guard().enforced_uid(), Some(1000));
}
