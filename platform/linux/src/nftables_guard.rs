use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// nftables family owned by Focus.
pub const FOCUS_NFT_FAMILY: &str = "inet";
/// nftables table owned by Focus.
pub const FOCUS_NFT_TABLE: &str = "focus";
/// Focus-owned output base chain.
pub const FOCUS_NFT_OUTPUT_CHAIN: &str = "output";
/// Focus-owned IPv4 address set reserved for later network policy rules.
pub const FOCUS_NFT_BLOCKED_IPV4_SET: &str = "blocked_ipv4";
/// Focus-owned IPv6 address set reserved for later network policy rules.
pub const FOCUS_NFT_BLOCKED_IPV6_SET: &str = "blocked_ipv6";

const NFT_CANDIDATES: [&str; 2] = ["/usr/sbin/nft", "/usr/bin/nft"];
const WRITEABLE_BY_NON_OWNER: u32 = 0o022;

/// Error returned by Focus-owned nftables operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusNftablesError {
    UnsafeExecutor,
    ApplyFailed,
    VerificationFailed,
}

/// Narrow nftables authority limited to the Focus-owned table.
pub trait FocusNftablesControl {
    /// Replaces the complete Focus-owned nftables table with the desired transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the Focus-owned table cannot be replaced safely.
    fn replace_focus_table(
        &mut self,
        transaction: &FocusNftablesTransaction,
    ) -> Result<(), FocusNftablesError>;

    /// Verifies that the complete Focus-owned table matches the desired transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the Focus-owned table cannot be read back exactly.
    fn verify_focus_table(
        &mut self,
        transaction: &FocusNftablesTransaction,
    ) -> Result<(), FocusNftablesError>;

    /// Removes only the Focus-owned nftables table.
    ///
    /// # Errors
    ///
    /// Returns an error when the Focus-owned table cannot be removed safely.
    fn remove_focus_table(&mut self) -> Result<(), FocusNftablesError>;
}

/// Replaces and verifies only Focus-owned nftables state.
///
/// # Errors
///
/// Returns the underlying control error when replacement or verification fails.
pub fn reload_focus_nftables<C: FocusNftablesControl>(
    control: &mut C,
    transaction: &FocusNftablesTransaction,
) -> Result<(), FocusNftablesError> {
    control.replace_focus_table(transaction)?;
    control.verify_focus_table(transaction)
}

/// Removes only Focus-owned nftables state.
///
/// # Errors
///
/// Returns the underlying control error when the Focus-owned table cannot be removed safely.
pub fn remove_focus_nftables<C: FocusNftablesControl>(
    control: &mut C,
) -> Result<(), FocusNftablesError> {
    control.remove_focus_table()
}

/// One nftables command whose ownership scope is fixed to the Focus table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FocusNftablesCommand {
    kind: FocusNftablesCommandKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusNftablesCommandKind {
    DesiredTable,
}

impl FocusNftablesCommand {
    const fn desired_table() -> Self {
        Self {
            kind: FocusNftablesCommandKind::DesiredTable,
        }
    }

    /// Returns the fixed nftables family owned by this command.
    #[must_use]
    pub const fn family(self) -> &'static str {
        FOCUS_NFT_FAMILY
    }

    /// Returns the fixed nftables table owned by this command.
    #[must_use]
    pub const fn table(self) -> &'static str {
        FOCUS_NFT_TABLE
    }

    fn render(self) -> String {
        match self.kind {
            FocusNftablesCommandKind::DesiredTable => format!(
                "table {FOCUS_NFT_FAMILY} {FOCUS_NFT_TABLE} {{\n\
                 \tset {FOCUS_NFT_BLOCKED_IPV4_SET} {{\n\
                 \t\ttype ipv4_addr\n\
                 \t}}\n\
                 \tset {FOCUS_NFT_BLOCKED_IPV6_SET} {{\n\
                 \t\ttype ipv6_addr\n\
                 \t}}\n\
                 \tchain {FOCUS_NFT_OUTPUT_CHAIN} {{\n\
                 \t\ttype filter hook output priority 0; policy accept;\n\
                 \t}}\n\
                 }}"
            ),
        }
    }
}

/// Desired nftables transaction for Focus-owned firewall objects only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FocusNftablesTransaction {
    commands: Vec<FocusNftablesCommand>,
}

impl FocusNftablesTransaction {
    /// Creates the minimal Focus-owned nftables transaction.
    #[must_use]
    pub fn new() -> Self {
        Self {
            commands: vec![FocusNftablesCommand::desired_table()],
        }
    }

    /// Returns the typed commands in application order.
    #[must_use]
    pub fn commands(&self) -> &[FocusNftablesCommand] {
        &self.commands
    }

    /// Renders the complete desired Focus-owned table.
    #[must_use]
    pub fn render(&self) -> String {
        self.commands
            .iter()
            .copied()
            .map(FocusNftablesCommand::render)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Renders an atomic replacement script scoped to the Focus-owned table.
    #[must_use]
    pub fn replacement_script(&self) -> String {
        format!(
            "destroy table {FOCUS_NFT_FAMILY} {FOCUS_NFT_TABLE}\n{}\n",
            self.render()
        )
    }
}

impl Default for FocusNftablesTransaction {
    fn default() -> Self {
        Self::new()
    }
}

/// Production nftables control using only a fixed trusted nft executable.
#[derive(Debug, Clone)]
pub struct SystemNftablesControl {
    executable: Option<PathBuf>,
}

impl Default for SystemNftablesControl {
    fn default() -> Self {
        Self {
            executable: NFT_CANDIDATES
                .iter()
                .map(PathBuf::from)
                .find(|path| path.exists()),
        }
    }
}

impl SystemNftablesControl {
    fn trusted_executor_metadata(is_file: bool, owner_uid: u32, mode: u32) -> bool {
        is_file && owner_uid == 0 && mode & 0o111 != 0 && mode & WRITEABLE_BY_NON_OWNER == 0
    }

    fn trusted_path(path: &Path) -> Result<bool, FocusNftablesError> {
        let canonical = fs::canonicalize(path).map_err(|_| FocusNftablesError::UnsafeExecutor)?;
        let metadata = fs::metadata(canonical).map_err(|_| FocusNftablesError::UnsafeExecutor)?;
        Ok(Self::trusted_executor_metadata(
            metadata.is_file(),
            metadata.uid(),
            metadata.permissions().mode() & 0o777,
        ))
    }

    fn trusted_executable(&self) -> Result<&Path, FocusNftablesError> {
        let Some(executable) = self.executable.as_deref() else {
            return Err(FocusNftablesError::UnsafeExecutor);
        };
        if !Self::trusted_path(executable)? {
            return Err(FocusNftablesError::UnsafeExecutor);
        }
        Ok(executable)
    }

    fn apply_script(&self, script: &str) -> Result<(), FocusNftablesError> {
        let executable = self.trusted_executable()?;
        let mut child = Command::new(executable)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| FocusNftablesError::ApplyFailed)?;
        let write_result = child
            .stdin
            .as_mut()
            .ok_or(FocusNftablesError::ApplyFailed)
            .and_then(|stdin| {
                stdin
                    .write_all(script.as_bytes())
                    .map_err(|_| FocusNftablesError::ApplyFailed)
            });
        drop(child.stdin.take());
        let status = child.wait().map_err(|_| FocusNftablesError::ApplyFailed)?;
        write_result?;
        if status.success() {
            Ok(())
        } else {
            Err(FocusNftablesError::ApplyFailed)
        }
    }

    fn read_focus_table(&self) -> Result<String, FocusNftablesError> {
        let executable = self.trusted_executable()?;
        let output = Command::new(executable)
            .args(["-y", "list", "table", FOCUS_NFT_FAMILY, FOCUS_NFT_TABLE])
            .output()
            .map_err(|_| FocusNftablesError::VerificationFailed)?;
        if !output.status.success() {
            return Err(FocusNftablesError::VerificationFailed);
        }
        String::from_utf8(output.stdout).map_err(|_| FocusNftablesError::VerificationFailed)
    }

    fn normalize_listing(listing: &str) -> String {
        let mut normalized = String::new();
        for token in listing.split_whitespace() {
            if !normalized.is_empty() {
                normalized.push(' ');
            }
            normalized.push_str(token);
        }
        normalized
    }
}

impl FocusNftablesControl for SystemNftablesControl {
    fn replace_focus_table(
        &mut self,
        transaction: &FocusNftablesTransaction,
    ) -> Result<(), FocusNftablesError> {
        self.apply_script(&transaction.replacement_script())
    }

    fn verify_focus_table(
        &mut self,
        transaction: &FocusNftablesTransaction,
    ) -> Result<(), FocusNftablesError> {
        let observed = self.read_focus_table()?;
        if Self::normalize_listing(&observed) == Self::normalize_listing(&transaction.render()) {
            Ok(())
        } else {
            Err(FocusNftablesError::VerificationFailed)
        }
    }

    fn remove_focus_table(&mut self) -> Result<(), FocusNftablesError> {
        self.apply_script(&format!(
            "destroy table {FOCUS_NFT_FAMILY} {FOCUS_NFT_TABLE}\n"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::SystemNftablesControl;

    #[test]
    fn trusted_executor_requires_root_owned_non_writable_executable_file() {
        assert!(SystemNftablesControl::trusted_executor_metadata(
            true, 0, 0o755
        ));
        assert!(!SystemNftablesControl::trusted_executor_metadata(
            true, 1000, 0o755
        ));
        assert!(!SystemNftablesControl::trusted_executor_metadata(
            true, 0, 0o775
        ));
        assert!(!SystemNftablesControl::trusted_executor_metadata(
            true, 0, 0o644
        ));
        assert!(!SystemNftablesControl::trusted_executor_metadata(
            false, 0, 0o755
        ));
    }
}
