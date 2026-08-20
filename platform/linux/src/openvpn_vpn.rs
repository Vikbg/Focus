use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use crate::{PrivilegeBrokerError, VpnActionControl, VpnAdapter};

const FOCUS_CONFIG_ROOT: &str = "/etc/focus";
const FOCUS_OPENVPN_CONFIG_ROOT: &str = "/etc/focus/openvpn";
const OPENVPN_CANDIDATES: [&str; 2] = ["/usr/sbin/openvpn", "/usr/bin/openvpn"];
const SYSTEMD_RUN_CANDIDATES: [&str; 2] = ["/usr/bin/systemd-run", "/bin/systemd-run"];
const SYSTEMCTL_CANDIDATES: [&str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];
const WRITEABLE_BY_NON_OWNER: u32 = 0o022;
const VISIBLE_TO_NON_OWNER: u32 = 0o077;
const ALLOWED_INLINE_BLOCKS: &[&str] = &[
    "auth-user-pass",
    "ca",
    "cert",
    "crl-verify",
    "extra-certs",
    "key",
    "pkcs12",
    "secret",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
];
const REJECTED_CONFIG_DIRECTIVES: &[&str] = &[
    "askpass",
    "auth-gen-token-secret",
    "auth-user-pass",
    "auth-user-pass-verify",
    "ca",
    "capath",
    "cd",
    "cert",
    "chroot",
    "client-connect",
    "client-crresponse",
    "client-disconnect",
    "config",
    "crl-verify",
    "daemon",
    "dh",
    "down",
    "extra-certs",
    "http-proxy-user-pass",
    "ifconfig-pool-persist",
    "ipchange",
    "key",
    "learn-address",
    "log",
    "log-append",
    "mode",
    "pkcs12",
    "plugin",
    "replay-persist",
    "route-pre-down",
    "route-up",
    "script-security",
    "secret",
    "server",
    "server-bridge",
    "status",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "tls-crypt-v2-verify",
    "tls-export-cert",
    "tls-verify",
    "tmp-dir",
    "up",
    "writepid",
];

/// One pre-approved `OpenVPN` profile bound to a stable Focus VPN id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVpnProfile {
    id: u128,
    config: PathBuf,
}

impl OpenVpnProfile {
    /// Creates one pre-approved `OpenVPN` profile registration.
    #[must_use]
    pub fn new(id: u128, config: PathBuf) -> Self {
        Self { id, config }
    }
}

/// Narrow command dependency used by the `OpenVPN` adapter.
pub trait OpenVpnCommandControl {
    /// Returns whether the fixed production executor is trusted.
    ///
    /// # Errors
    ///
    /// Returns an error when executor trust cannot be established safely.
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError>;

    /// Returns whether one registered configuration remains trusted.
    ///
    /// # Errors
    ///
    /// Returns an error when configuration trust cannot be established safely.
    fn config_is_trusted(&self, config: &Path) -> Result<bool, PrivilegeBrokerError>;

    /// Starts one approved `OpenVPN` profile under a deterministic Focus-owned systemd unit.
    ///
    /// # Errors
    ///
    /// Returns an error when the service cannot be started.
    fn start_service(&mut self, unit: &str, config: &Path) -> Result<(), PrivilegeBrokerError>;

    /// Stops one deterministic Focus-owned `OpenVPN` systemd unit.
    ///
    /// # Errors
    ///
    /// Returns an error when the service cannot be stopped.
    fn stop_service(&mut self, unit: &str) -> Result<(), PrivilegeBrokerError>;
}

/// Provider-specific `OpenVPN` implementation of the provider-neutral VPN contract.
#[derive(Debug)]
pub struct OpenVpnAdapter<C> {
    profiles: Vec<OpenVpnProfile>,
    command_control: C,
}

impl<C> OpenVpnAdapter<C> {
    /// Creates the adapter from pre-approved profiles and one narrow command control.
    #[must_use]
    pub fn new<I>(profiles: I, command_control: C) -> Self
    where
        I: IntoIterator<Item = OpenVpnProfile>,
    {
        Self {
            profiles: profiles.into_iter().collect(),
            command_control,
        }
    }

    /// Returns the command dependency for deterministic tests and diagnostics.
    #[must_use]
    pub const fn command_control(&self) -> &C {
        &self.command_control
    }

    fn config_for_id(&self, id: u128) -> Option<PathBuf> {
        let mut matches = self.profiles.iter().filter(|profile| profile.id == id);
        let profile = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(profile.config.clone())
    }

    fn unit_for_id(id: u128) -> String {
        format!("focus-openvpn-{id}.service")
    }
}

impl<C: OpenVpnCommandControl> VpnAdapter for OpenVpnAdapter<C> {
    fn connect(&mut self, id: u128) -> Result<(), PrivilegeBrokerError> {
        let config = self
            .config_for_id(id)
            .ok_or(PrivilegeBrokerError::ActionNotApproved)?;
        if !self.command_control.executor_is_trusted()? {
            return Err(PrivilegeBrokerError::UnsafeExecutor);
        }
        if !self.command_control.config_is_trusted(&config)? {
            return Err(PrivilegeBrokerError::ActionNotApproved);
        }
        self.command_control
            .start_service(&Self::unit_for_id(id), &config)
    }

    fn disconnect(&mut self, id: u128) -> Result<(), PrivilegeBrokerError> {
        self.config_for_id(id)
            .ok_or(PrivilegeBrokerError::ActionNotApproved)?;
        self.command_control.stop_service(&Self::unit_for_id(id))
    }
}

impl<C: OpenVpnCommandControl> VpnActionControl for OpenVpnAdapter<C> {
    fn connect_vpn(&mut self, id: u128) -> Result<(), PrivilegeBrokerError> {
        VpnAdapter::connect(self, id)
    }

    fn disconnect_vpn(&mut self, id: u128) -> Result<(), PrivilegeBrokerError> {
        VpnAdapter::disconnect(self, id)
    }
}

/// Production boundary for fixed `OpenVPN`, systemd-run, and systemctl executors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemOpenVpnCommandControl {
    openvpn: Option<PathBuf>,
    systemd_run: Option<PathBuf>,
    systemctl: Option<PathBuf>,
}

impl Default for SystemOpenVpnCommandControl {
    fn default() -> Self {
        Self {
            openvpn: OPENVPN_CANDIDATES
                .iter()
                .map(PathBuf::from)
                .find(|candidate| candidate.exists()),
            systemd_run: SYSTEMD_RUN_CANDIDATES
                .iter()
                .map(PathBuf::from)
                .find(|candidate| candidate.exists()),
            systemctl: SYSTEMCTL_CANDIDATES
                .iter()
                .map(PathBuf::from)
                .find(|candidate| candidate.exists()),
        }
    }
}

impl SystemOpenVpnCommandControl {
    fn trusted_executor_metadata(is_file: bool, owner_uid: u32, mode: u32) -> bool {
        is_file && owner_uid == 0 && mode & 0o111 != 0 && mode & WRITEABLE_BY_NON_OWNER == 0
    }

    fn trusted_executor_path(path: &Path) -> Result<bool, PrivilegeBrokerError> {
        let canonical = fs::canonicalize(path).map_err(|_| PrivilegeBrokerError::UnsafeExecutor)?;
        let metadata = fs::metadata(canonical).map_err(|_| PrivilegeBrokerError::UnsafeExecutor)?;
        Ok(Self::trusted_executor_metadata(
            metadata.is_file(),
            metadata.uid(),
            metadata.permissions().mode() & 0o777,
        ))
    }

    fn trusted_config_root_metadata(
        is_dir: bool,
        is_symlink: bool,
        owner_uid: u32,
        mode: u32,
    ) -> bool {
        is_dir && !is_symlink && owner_uid == 0 && mode & WRITEABLE_BY_NON_OWNER == 0
    }

    fn trusted_config_metadata(is_file: bool, is_symlink: bool, owner_uid: u32, mode: u32) -> bool {
        is_file
            && !is_symlink
            && owner_uid == 0
            && mode & VISIBLE_TO_NON_OWNER == 0
            && mode & 0o400 != 0
    }

    fn config_path_is_in_scope(config: &Path) -> bool {
        config.parent() == Some(Path::new(FOCUS_OPENVPN_CONFIG_ROOT))
            && matches!(
                config.extension().and_then(|extension| extension.to_str()),
                Some("ovpn" | "conf")
            )
    }

    fn config_roots_are_trusted() -> Result<bool, PrivilegeBrokerError> {
        for root in [FOCUS_CONFIG_ROOT, FOCUS_OPENVPN_CONFIG_ROOT] {
            let metadata =
                fs::symlink_metadata(root).map_err(|_| PrivilegeBrokerError::ActionNotApproved)?;
            if !Self::trusted_config_root_metadata(
                metadata.is_dir(),
                metadata.file_type().is_symlink(),
                metadata.uid(),
                metadata.permissions().mode() & 0o777,
            ) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn config_directive_is_rejected(directive: &str) -> bool {
        directive.starts_with("management") || REJECTED_CONFIG_DIRECTIVES.contains(&directive)
    }

    fn safe_config_contents(contents: &str) -> bool {
        let mut inline_block: Option<String> = None;

        for raw_line in contents.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            let lowercase = line.to_ascii_lowercase();
            if let Some(block) = inline_block.as_deref() {
                if lowercase == format!("</{block}>") {
                    inline_block = None;
                    continue;
                }
                if lowercase.starts_with('<') && lowercase.ends_with('>') {
                    return false;
                }
                continue;
            }

            if lowercase.starts_with("</") {
                return false;
            }
            if lowercase.starts_with('<') {
                let Some(tag) = lowercase
                    .strip_prefix('<')
                    .and_then(|value| value.strip_suffix('>'))
                else {
                    return false;
                };
                if tag.is_empty()
                    || tag.starts_with('/')
                    || tag.split_whitespace().count() != 1
                    || !ALLOWED_INLINE_BLOCKS.contains(&tag)
                {
                    return false;
                }
                inline_block = Some(tag.to_owned());
                continue;
            }

            let Some(raw_directive) = lowercase.split_whitespace().next() else {
                return false;
            };
            let directive = raw_directive.trim_start_matches("--");
            if directive.is_empty() || Self::config_directive_is_rejected(directive) {
                return false;
            }
        }

        inline_block.is_none()
    }
}

impl OpenVpnCommandControl for SystemOpenVpnCommandControl {
    fn executor_is_trusted(&self) -> Result<bool, PrivilegeBrokerError> {
        let (Some(openvpn), Some(systemd_run), Some(systemctl)) = (
            self.openvpn.as_deref(),
            self.systemd_run.as_deref(),
            self.systemctl.as_deref(),
        ) else {
            return Ok(false);
        };

        for executor in [openvpn, systemd_run, systemctl] {
            if !Self::trusted_executor_path(executor)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn config_is_trusted(&self, config: &Path) -> Result<bool, PrivilegeBrokerError> {
        if !Self::config_path_is_in_scope(config) || !Self::config_roots_are_trusted()? {
            return Ok(false);
        }

        let metadata =
            fs::symlink_metadata(config).map_err(|_| PrivilegeBrokerError::ActionNotApproved)?;
        if !Self::trusted_config_metadata(
            metadata.is_file(),
            metadata.file_type().is_symlink(),
            metadata.uid(),
            metadata.permissions().mode() & 0o777,
        ) {
            return Ok(false);
        }

        let contents =
            fs::read_to_string(config).map_err(|_| PrivilegeBrokerError::ActionNotApproved)?;
        Ok(Self::safe_config_contents(&contents))
    }

    fn start_service(&mut self, _unit: &str, _config: &Path) -> Result<(), PrivilegeBrokerError> {
        Err(PrivilegeBrokerError::ActionNotApproved)
    }

    fn stop_service(&mut self, _unit: &str) -> Result<(), PrivilegeBrokerError> {
        Err(PrivilegeBrokerError::ActionNotApproved)
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{OpenVpnCommandControl, SystemOpenVpnCommandControl};

    #[test]
    fn trusted_openvpn_executor_requires_root_owned_non_writable_executable_file() {
        assert!(SystemOpenVpnCommandControl::trusted_executor_metadata(
            true, 0, 0o755
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_executor_metadata(
            true, 1000, 0o755
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_executor_metadata(
            true, 0, 0o775
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_executor_metadata(
            true, 0, 0o644
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_executor_metadata(
            false, 0, 0o755
        ));
    }

    #[test]
    fn production_executor_trust_requires_all_three_trusted_paths() {
        let trusted = PathBuf::from("/bin/sh");
        let control = SystemOpenVpnCommandControl {
            openvpn: Some(trusted.clone()),
            systemd_run: Some(trusted.clone()),
            systemctl: Some(trusted.clone()),
        };
        assert_eq!(control.executor_is_trusted(), Ok(true));

        let missing_openvpn = SystemOpenVpnCommandControl {
            openvpn: None,
            systemd_run: Some(trusted.clone()),
            systemctl: Some(trusted),
        };
        assert_eq!(missing_openvpn.executor_is_trusted(), Ok(false));
    }

    #[test]
    fn trusted_openvpn_config_root_requires_root_owned_non_writable_directory() {
        assert!(SystemOpenVpnCommandControl::trusted_config_root_metadata(
            true, false, 0, 0o755
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_config_root_metadata(
            false, false, 0, 0o755
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_config_root_metadata(
            true, true, 0, 0o755
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_config_root_metadata(
            true, false, 1000, 0o755
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_config_root_metadata(
            true, false, 0, 0o775
        ));
    }

    #[test]
    fn trusted_openvpn_config_requires_root_owned_private_regular_file() {
        assert!(SystemOpenVpnCommandControl::trusted_config_metadata(
            true, false, 0, 0o600
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_config_metadata(
            false, false, 0, 0o600
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_config_metadata(
            true, true, 0, 0o600
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_config_metadata(
            true, false, 1000, 0o600
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_config_metadata(
            true, false, 0, 0o640
        ));
        assert!(!SystemOpenVpnCommandControl::trusted_config_metadata(
            true, false, 0, 0o200
        ));
    }

    #[test]
    fn openvpn_config_scope_allows_only_direct_ovpn_or_conf_children() {
        assert!(SystemOpenVpnCommandControl::config_path_is_in_scope(
            Path::new("/etc/focus/openvpn/study.ovpn")
        ));
        assert!(SystemOpenVpnCommandControl::config_path_is_in_scope(
            Path::new("/etc/focus/openvpn/study.conf")
        ));
        assert!(!SystemOpenVpnCommandControl::config_path_is_in_scope(
            Path::new("/etc/focus/openvpn/nested/study.ovpn")
        ));
        assert!(!SystemOpenVpnCommandControl::config_path_is_in_scope(
            Path::new("/etc/focus/openvpn/study.txt")
        ));
        assert!(!SystemOpenVpnCommandControl::config_path_is_in_scope(
            Path::new("/tmp/study.ovpn")
        ));
    }

    #[test]
    fn openvpn_config_accepts_client_profile_with_inline_credentials() {
        let config = r#"
client
dev tun
proto udp
remote vpn.example 1194
nobind
persist-key
persist-tun
remote-cert-tls server
<ca>
-----BEGIN CERTIFICATE-----
inline-ca
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
inline-cert
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
inline-key
-----END PRIVATE KEY-----
</key>
<tls-crypt>
inline-tls-crypt
</tls-crypt>
<auth-user-pass>
study-user
study-password
</auth-user-pass>
"#;

        assert!(SystemOpenVpnCommandControl::safe_config_contents(config));
    }

    #[test]
    fn openvpn_config_rejects_privileged_execution_control_and_external_file_directives() {
        for directive in [
            "up /tmp/hook",
            "down /tmp/hook",
            "route-up /tmp/hook",
            "route-pre-down /tmp/hook",
            "ipchange /tmp/hook",
            "tls-verify /tmp/hook",
            "auth-user-pass-verify /tmp/hook via-file",
            "client-connect /tmp/hook",
            "client-disconnect /tmp/hook",
            "learn-address /tmp/hook",
            "tls-crypt-v2-verify /tmp/hook",
            "script-security 3",
            "plugin /tmp/plugin.so",
            "management 127.0.0.1 7505",
            "management-query-remote",
            "daemon",
            "writepid /tmp/openvpn.pid",
            "config /tmp/other.conf",
            "cd /tmp",
            "chroot /tmp/root",
            "tmp-dir /tmp",
            "ca /tmp/ca.crt",
            "cert /tmp/client.crt",
            "key /tmp/client.key",
            "pkcs12 /tmp/client.p12",
            "secret /tmp/static.key",
            "crl-verify /tmp/crl.pem",
            "extra-certs /tmp/chain.pem",
            "tls-auth /tmp/ta.key 1",
            "tls-crypt /tmp/tc.key",
            "tls-crypt-v2 /tmp/tcv2.key",
            "auth-user-pass /tmp/credentials",
            "askpass /tmp/passphrase",
            "http-proxy-user-pass /tmp/proxy-creds",
            "auth-gen-token-secret /tmp/token-secret",
            "log /tmp/openvpn.log",
            "log-append /tmp/openvpn.log",
            "status /tmp/openvpn.status",
            "tls-export-cert /tmp/certs",
            "server 10.8.0.0 255.255.255.0",
            "server-bridge 10.8.0.4 255.255.255.0 10.8.0.50 10.8.0.100",
            "mode server",
            "--UP /tmp/hook",
        ] {
            assert!(
                !SystemOpenVpnCommandControl::safe_config_contents(directive),
                "dangerous OpenVPN directive was accepted: {directive}"
            );
        }
    }

    #[test]
    fn openvpn_config_rejects_unknown_mismatched_or_unterminated_inline_blocks() {
        for config in [
            "<unknown>\nvalue\n</unknown>",
            "<ca>\nvalue\n</cert>",
            "<key>\nvalue",
            "</ca>",
            "<ca>\n<key>\nvalue\n</key>\n</ca>",
        ] {
            assert!(!SystemOpenVpnCommandControl::safe_config_contents(config));
        }
    }
}
