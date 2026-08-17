use std::{error::Error, fmt, fmt::Write as _};

use focus_core::{
    ExecutableMatcher, ExecutionOrigin, ObservedExecutable, PackageIdentity, PackageKind,
};

/// Read-only facts collected around one Linux execution attempt.
///
/// Package fields in this type are already verified facts produced by the Linux collector. This
/// classifier never promotes process-controlled environment strings into stable package identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxExecutionFacts {
    argv: Vec<String>,
    cgroup: Option<String>,
    parent: Option<ObservedExecutable>,
    verified_flatpak_app_id: Option<String>,
    verified_snap_package_id: Option<String>,
    verified_appimage_digest: Option<[u8; 32]>,
    verified_wine_target_digest: Option<[u8; 32]>,
}

impl LinuxExecutionFacts {
    /// Creates execution facts with the observed command line.
    #[must_use]
    pub const fn new(argv: Vec<String>) -> Self {
        Self {
            argv,
            cgroup: None,
            parent: None,
            verified_flatpak_app_id: None,
            verified_snap_package_id: None,
            verified_appimage_digest: None,
            verified_wine_target_digest: None,
        }
    }

    /// Adds the unified cgroup path for the process.
    #[must_use]
    pub fn with_cgroup(mut self, cgroup: impl Into<String>) -> Self {
        self.cgroup = Some(cgroup.into());
        self
    }

    /// Adds the stable direct-parent executable identity.
    #[must_use]
    pub fn with_parent(mut self, parent: ObservedExecutable) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Adds an application ID verified from authoritative Flatpak process metadata.
    #[must_use]
    pub fn with_verified_flatpak_app_id(mut self, app_id: impl Into<String>) -> Self {
        self.verified_flatpak_app_id = Some(app_id.into());
        self
    }

    /// Adds a Snap package ID verified from trusted Linux package metadata.
    #[must_use]
    pub fn with_verified_snap_package_id(mut self, package_id: impl Into<String>) -> Self {
        self.verified_snap_package_id = Some(package_id.into());
        self
    }

    /// Adds the digest of an `AppImage` backing file verified by the Linux collector.
    #[must_use]
    pub const fn with_verified_appimage_digest(mut self, digest: [u8; 32]) -> Self {
        self.verified_appimage_digest = Some(digest);
        self
    }

    /// Adds the digest of a Wine target executable verified by the Linux collector.
    #[must_use]
    pub const fn with_verified_wine_target_digest(mut self, digest: [u8; 32]) -> Self {
        self.verified_wine_target_digest = Some(digest);
        self
    }
}

/// Stable parent identities that can refine a Linux launch context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionContextClassifier {
    ide_parent_matchers: Vec<ExecutableMatcher>,
}

impl ExecutionContextClassifier {
    /// Creates a classifier with the stable identities of trusted IDE launchers.
    #[must_use]
    pub const fn new(ide_parent_matchers: Vec<ExecutableMatcher>) -> Self {
        Self {
            ide_parent_matchers,
        }
    }

    fn parent_is_ide(&self, parent: &ObservedExecutable) -> bool {
        self.ide_parent_matchers
            .iter()
            .any(|matcher| matcher.matches(parent))
    }
}

/// Error returned when Linux execution facts cannot be classified safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionContextError {
    AmbiguousPackageMarkers,
    InvalidWineMarker,
}

impl fmt::Display for ExecutionContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousPackageMarkers => {
                formatter.write_str("conflicting verified Linux package execution markers")
            }
            Self::InvalidWineMarker => formatter
                .write_str("verified Wine target digest was supplied for a non-Wine loader"),
        }
    }
}

impl Error for ExecutionContextError {}

/// Enriches a stable executable identity with verified Linux package, parent, and launch facts.
///
/// Package markers use stable package IDs or verified backing-file digests supplied by the Linux
/// collector. Conflicting verified package markers are rejected instead of being resolved by
/// priority. Untrusted environment strings are not consulted by this classifier.
///
/// # Errors
///
/// Returns an error when verified package markers conflict or a verified Wine target digest is
/// attached to a process that is not a recognized Wine loader.
pub fn enrich_execution_context(
    mut executable: ObservedExecutable,
    facts: &LinuxExecutionFacts,
    classifier: &ExecutionContextClassifier,
) -> Result<ObservedExecutable, ExecutionContextError> {
    let flatpak = non_empty(facts.verified_flatpak_app_id.as_deref());
    let snap = non_empty(facts.verified_snap_package_id.as_deref());
    let appimage = facts.verified_appimage_digest;
    let wine = if let Some(digest) = facts.verified_wine_target_digest {
        if !is_wine_loader(executable.canonical_path()) {
            return Err(ExecutionContextError::InvalidWineMarker);
        }
        Some(digest)
    } else {
        None
    };

    let strong_markers = usize::from(flatpak.is_some())
        + usize::from(snap.is_some())
        + usize::from(appimage.is_some())
        + usize::from(wine.is_some());
    if strong_markers > 1 {
        return Err(ExecutionContextError::AmbiguousPackageMarkers);
    }

    if let Some(app_id) = flatpak {
        executable = executable
            .with_package(PackageIdentity::new(PackageKind::Flatpak, app_id))
            .with_origin(ExecutionOrigin::Flatpak);
    } else if let Some(name) = snap {
        executable = executable
            .with_package(PackageIdentity::new(PackageKind::Snap, name))
            .with_origin(ExecutionOrigin::Snap);
    } else if let Some(digest) = appimage {
        executable = executable
            .with_package(PackageIdentity::new(
                PackageKind::AppImage,
                digest_identifier(digest),
            ))
            .with_origin(ExecutionOrigin::AppImage);
    } else if let Some(digest) = wine {
        executable = executable
            .with_package(PackageIdentity::new(
                PackageKind::Wine,
                digest_identifier(digest),
            ))
            .with_origin(ExecutionOrigin::Wine);
    } else {
        let origin = generic_origin(&executable, facts, classifier);
        executable = executable.with_origin(origin);
    }

    if let Some(parent) = facts.parent.clone() {
        executable = executable.with_parent(parent);
    }
    Ok(executable)
}

fn generic_origin(
    executable: &ObservedExecutable,
    facts: &LinuxExecutionFacts,
    classifier: &ExecutionContextClassifier,
) -> ExecutionOrigin {
    if facts.cgroup.as_deref().is_some_and(is_container_cgroup) {
        return ExecutionOrigin::Container;
    }
    if facts.cgroup.as_deref().is_some_and(is_user_systemd_cgroup) {
        return ExecutionOrigin::UserSystemd;
    }
    if let Some(parent) = facts.parent.as_ref() {
        if classifier.parent_is_ide(parent) {
            return ExecutionOrigin::IdeChild;
        }
        if is_cron_parent(parent) {
            return ExecutionOrigin::Cron;
        }
    }
    if is_interpreter(executable.canonical_path()) && facts.argv.len() > 1 {
        return ExecutionOrigin::Interpreter;
    }
    ExecutionOrigin::Direct
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.trim().is_empty())
}

fn is_wine_loader(path: &str) -> bool {
    matches!(file_name(path), "wine" | "wine64" | "wine-preloader")
}

fn is_interpreter(path: &str) -> bool {
    matches!(
        file_name(path),
        "sh" | "bash"
            | "dash"
            | "zsh"
            | "fish"
            | "python"
            | "python3"
            | "node"
            | "nodejs"
            | "ruby"
            | "perl"
            | "php"
    )
}

fn is_cron_parent(parent: &ObservedExecutable) -> bool {
    parent.filesystem_identity().is_some()
        && matches!(
            parent.canonical_path(),
            "/usr/sbin/cron" | "/usr/sbin/crond"
        )
}

fn is_user_systemd_cgroup(cgroup: &str) -> bool {
    cgroup.contains("/user.slice/") && cgroup.contains("/app.slice/")
}

fn is_container_cgroup(cgroup: &str) -> bool {
    cgroup.contains("/docker/")
        || cgroup.contains("docker-")
        || cgroup.contains("kubepods")
        || cgroup.contains("libpod-")
        || cgroup.contains("containerd")
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn digest_identifier(digest: [u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
