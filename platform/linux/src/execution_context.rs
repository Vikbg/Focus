use std::{error::Error, fmt, fmt::Write as _};

use focus_core::{
    ExecutableMatcher, ExecutionOrigin, ObservedExecutable, PackageIdentity, PackageKind,
};

/// Read-only facts collected around one Linux execution attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxExecutionFacts {
    argv: Vec<String>,
    environment: Vec<(String, String)>,
    cgroup: Option<String>,
    parent: Option<ObservedExecutable>,
    flatpak_app_id: Option<String>,
    appimage_digest: Option<[u8; 32]>,
    wine_target_digest: Option<[u8; 32]>,
}

impl LinuxExecutionFacts {
    /// Creates execution facts with the observed command line.
    #[must_use]
    pub const fn new(argv: Vec<String>) -> Self {
        Self {
            argv,
            environment: Vec::new(),
            cgroup: None,
            parent: None,
            flatpak_app_id: None,
            appimage_digest: None,
            wine_target_digest: None,
        }
    }

    /// Adds one environment fact.
    #[must_use]
    pub fn with_environment(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.environment.push((key.into(), value.into()));
        self
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

    /// Adds an application ID read from authoritative Flatpak process metadata.
    #[must_use]
    pub fn with_flatpak_app_id(mut self, app_id: impl Into<String>) -> Self {
        self.flatpak_app_id = Some(app_id.into());
        self
    }

    /// Adds the digest of the AppImage backing file after it has been observed safely.
    #[must_use]
    pub const fn with_appimage_digest(mut self, digest: [u8; 32]) -> Self {
        self.appimage_digest = Some(digest);
        self
    }

    /// Adds the digest of the Windows executable targeted by a Wine loader.
    #[must_use]
    pub const fn with_wine_target_digest(mut self, digest: [u8; 32]) -> Self {
        self.wine_target_digest = Some(digest);
        self
    }

    fn environment_value(&self, key: &str) -> Option<&str> {
        self.environment
            .iter()
            .rev()
            .find_map(|(candidate, value)| (candidate == key).then_some(value.as_str()))
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
    IncompleteAppImageMarker,
    InvalidWineMarker,
}

impl fmt::Display for ExecutionContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmbiguousPackageMarkers => {
                formatter.write_str("conflicting Linux package execution markers")
            }
            Self::IncompleteAppImageMarker => {
                formatter.write_str("AppImage marker is missing a verified backing-file digest")
            }
            Self::InvalidWineMarker => {
                formatter.write_str("Wine target digest was supplied for a non-Wine loader")
            }
        }
    }
}

impl Error for ExecutionContextError {}

/// Enriches a stable executable identity with Linux package, parent, and launch-context facts.
///
/// Package markers use stable package IDs or verified backing-file digests. Conflicting strong
/// package markers are rejected instead of being resolved by priority.
///
/// # Errors
///
/// Returns an error when strong package markers conflict, an AppImage marker lacks a verified
/// digest, or a Wine target digest is attached to a process that is not a recognized Wine loader.
pub fn enrich_execution_context(
    mut executable: ObservedExecutable,
    facts: &LinuxExecutionFacts,
    classifier: &ExecutionContextClassifier,
) -> Result<ObservedExecutable, ExecutionContextError> {
    let flatpak = non_empty(facts.flatpak_app_id.as_deref());
    let snap = non_empty(facts.environment_value("SNAP_NAME"));
    let appimage_path = non_empty(facts.environment_value("APPIMAGE"));
    let appimage = match (appimage_path, facts.appimage_digest) {
        (Some(_), Some(digest)) => Some(digest),
        (Some(_), None) => return Err(ExecutionContextError::IncompleteAppImageMarker),
        (None, _) => None,
    };
    let wine = if let Some(digest) = facts.wine_target_digest {
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
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
