/// nftables family owned by Focus.
pub const FOCUS_NFT_FAMILY: &str = "inet";
/// nftables table owned by Focus.
pub const FOCUS_NFT_TABLE: &str = "focus";

/// One nftables command whose ownership scope is fixed to the Focus table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FocusNftablesCommand {
    kind: FocusNftablesCommandKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusNftablesCommandKind {
    EnsureTable,
}

impl FocusNftablesCommand {
    const fn ensure_table() -> Self {
        Self {
            kind: FocusNftablesCommandKind::EnsureTable,
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
            FocusNftablesCommandKind::EnsureTable => {
                format!("add table {FOCUS_NFT_FAMILY} {FOCUS_NFT_TABLE}")
            }
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
            commands: vec![FocusNftablesCommand::ensure_table()],
        }
    }

    /// Returns the typed commands in application order.
    #[must_use]
    pub fn commands(&self) -> &[FocusNftablesCommand] {
        &self.commands
    }

    /// Renders the typed Focus-owned commands as nft input.
    #[must_use]
    pub fn render(&self) -> String {
        self.commands
            .iter()
            .copied()
            .map(FocusNftablesCommand::render)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for FocusNftablesTransaction {
    fn default() -> Self {
        Self::new()
    }
}
