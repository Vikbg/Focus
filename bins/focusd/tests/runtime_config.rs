use std::path::Path;

use focusd::{RuntimeConfig, RuntimeConfigError};

#[test]
fn missing_deployment_uid_is_rejected_instead_of_falling_back_to_effective_uid() {
    assert_eq!(
        RuntimeConfig::from_values(None, None),
        Err(RuntimeConfigError::MissingAllowedUid)
    );
}

#[test]
fn explicit_desktop_uid_and_cli_path_are_preserved() {
    let config = RuntimeConfig::from_values(Some("1000"), Some("/opt/focus/bin/focusctl")).unwrap();

    assert_eq!(config.allowed_uid(), 1000);
    assert_eq!(config.cli_executable(), Path::new("/opt/focus/bin/focusctl"));
}

#[test]
fn invalid_deployment_uid_is_rejected() {
    assert_eq!(
        RuntimeConfig::from_values(Some("desktop-user"), None),
        Err(RuntimeConfigError::InvalidAllowedUid)
    );
}

#[test]
fn absent_cli_override_uses_installed_cli_path_only() {
    let config = RuntimeConfig::from_values(Some("1000"), None).unwrap();

    assert_eq!(config.cli_executable(), Path::new("/usr/bin/focusctl"));
}
