//! Platform-independent process enforcement semantics.

use crate::{BlockReason, Decision};

/// Origin that caused an executable to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionOrigin {
    Direct,
    Interpreter,
    IdeChild,
    UserSystemd,
    Cron,
    Container,
    AppImage,
    Flatpak,
    Snap,
    Wine,
}

/// Package systems that can contribute a stable executable identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PackageKind {
    Native,
    Flatpak,
    Snap,
    AppImage,
    Wine,
}

/// Stable package identity attached to an observed executable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageIdentity {
    kind: PackageKind,
    id: String,
}

impl PackageIdentity {
    /// Creates a package identity from its package system and stable identifier.
    #[must_use]
    pub fn new(kind: PackageKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }

    /// Returns the package system.
    #[must_use]
    pub const fn kind(&self) -> PackageKind {
        self.kind
    }

    /// Returns the package identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Platform observation used by the process policy engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedExecutable {
    canonical_path: String,
    device: Option<u64>,
    inode: Option<u64>,
    digest: Option<[u8; 32]>,
    package: Option<PackageIdentity>,
    origin: ExecutionOrigin,
    parent: Option<Box<ObservedExecutable>>,
}

impl ObservedExecutable {
    /// Creates an observation with only a canonical executable path.
    #[must_use]
    pub fn new(canonical_path: impl Into<String>) -> Self {
        Self {
            canonical_path: canonical_path.into(),
            device: None,
            inode: None,
            digest: None,
            package: None,
            origin: ExecutionOrigin::Direct,
            parent: None,
        }
    }

    /// Adds the filesystem device and inode identity.
    #[must_use]
    pub const fn with_filesystem_identity(mut self, device: u64, inode: u64) -> Self {
        self.device = Some(device);
        self.inode = Some(inode);
        self
    }

    /// Adds a cryptographic executable digest.
    #[must_use]
    pub const fn with_digest(mut self, digest: [u8; 32]) -> Self {
        self.digest = Some(digest);
        self
    }

    /// Adds package metadata.
    #[must_use]
    pub fn with_package(mut self, package: PackageIdentity) -> Self {
        self.package = Some(package);
        self
    }

    /// Adds the observed execution origin.
    #[must_use]
    pub const fn with_origin(mut self, origin: ExecutionOrigin) -> Self {
        self.origin = origin;
        self
    }

    /// Adds the stable identity of the direct parent process.
    #[must_use]
    pub fn with_parent(mut self, parent: ObservedExecutable) -> Self {
        self.parent = Some(Box::new(parent));
        self
    }

    /// Returns the canonical executable path supplied by the platform backend.
    #[must_use]
    pub fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    /// Returns the filesystem identity when both fields are known.
    #[must_use]
    pub const fn filesystem_identity(&self) -> Option<(u64, u64)> {
        match (self.device, self.inode) {
            (Some(device), Some(inode)) => Some((device, inode)),
            _ => None,
        }
    }

    /// Returns the executable digest when available.
    #[must_use]
    pub const fn digest(&self) -> Option<[u8; 32]> {
        self.digest
    }

    /// Returns package metadata when available.
    #[must_use]
    pub const fn package(&self) -> Option<&PackageIdentity> {
        self.package.as_ref()
    }

    /// Returns the execution origin.
    #[must_use]
    pub const fn origin(&self) -> ExecutionOrigin {
        self.origin
    }

    /// Returns the direct parent identity when it was collected.
    #[must_use]
    pub fn parent(&self) -> Option<&ObservedExecutable> {
        self.parent.as_deref()
    }

    const fn has_stable_identity(&self) -> bool {
        self.digest.is_some()
            || matches!((self.device, self.inode), (Some(_), Some(_)))
            || self.package.is_some()
    }
}

/// Stable selectors supported by a compiled process rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutableMatcher {
    Digest([u8; 32]),
    Filesystem { device: u64, inode: u64 },
    Package(PackageIdentity),
    CanonicalPath(String),
}

impl ExecutableMatcher {
    /// Returns whether this stable selector matches the observed executable.
    #[must_use]
    pub fn matches(&self, executable: &ObservedExecutable) -> bool {
        match self {
            Self::Digest(expected) => executable.digest == Some(*expected),
            Self::Filesystem { device, inode } => {
                executable.filesystem_identity() == Some((*device, *inode))
            }
            Self::Package(expected) => executable.package.as_ref() == Some(expected),
            Self::CanonicalPath(expected) => executable.canonical_path == *expected,
        }
    }
}

/// One compiled process rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRule {
    matcher: ExecutableMatcher,
    decision: Decision,
}

impl ProcessRule {
    /// Creates an explicit block rule.
    #[must_use]
    pub const fn block(matcher: ExecutableMatcher) -> Self {
        Self {
            matcher,
            decision: Decision::Block(BlockReason::ExplicitBlock),
        }
    }

    fn matches(&self, executable: &ObservedExecutable) -> bool {
        self.matcher.matches(executable)
    }
}

/// Immutable process policy compiled for one strict session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEnforcementPlan {
    policy_digest: [u8; 32],
    strict: bool,
    rules: Vec<ProcessRule>,
    trusted_workspace_roots: Vec<String>,
}

impl ProcessEnforcementPlan {
    /// Creates a strict process plan bound to the frozen policy digest.
    #[must_use]
    pub const fn strict(
        policy_digest: [u8; 32],
        rules: Vec<ProcessRule>,
        trusted_workspace_roots: Vec<String>,
    ) -> Self {
        Self {
            policy_digest,
            strict: true,
            rules,
            trusted_workspace_roots,
        }
    }

    /// Returns the frozen policy digest this plan enforces.
    #[must_use]
    pub const fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    /// Decides whether an observed executable may run.
    #[must_use]
    pub fn decide(&self, executable: &ObservedExecutable) -> Decision {
        if let Some(rule) = self.rules.iter().find(|rule| rule.matches(executable)) {
            return rule.decision;
        }

        if !executable.has_stable_identity() {
            return Decision::FailClosed(BlockReason::Unknown);
        }

        if self
            .trusted_workspace_roots
            .iter()
            .any(|root| path_is_within(executable.canonical_path(), root))
        {
            return Decision::Allow;
        }

        if self.strict {
            Decision::FailClosed(BlockReason::Unknown)
        } else {
            Decision::Allow
        }
    }
}

fn path_is_within(path: &str, root: &str) -> bool {
    if path == root {
        return true;
    }
    let Some(remainder) = path.strip_prefix(root) else {
        return false;
    };
    remainder.starts_with('/')
}
