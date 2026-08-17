use focusd::{RuntimeConfig, linux_backend_from_config};

#[test]
fn runtime_config_uid_builds_uid_scoped_linux_backend() {
    let config = RuntimeConfig::from_values(Some("1000"), None).unwrap();

    let backend = linux_backend_from_config(&config);

    assert_eq!(backend.process_control().enforced_uid(), Some(1000));
    assert_eq!(backend.process_guard().enforced_uid(), Some(1000));
}
