use std::{
    collections::BTreeMap,
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use focus_core::{ExecutableMatcher, ExecutionOrigin, PackageIdentity, PackageKind};
use focus_linux::{
    ExecutionContextClassifier, LinuxExecutionFactSource, collect_execution_observation,
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn fixture_dir() -> PathBuf {
    let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "focus-execution-facts-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn executable(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, contents).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn stat(pid: u32) -> String {
    let fields = (4_u8..=21)
        .map(|field| field.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let starttime = 10_000_u64 + u64::from(pid);
    format!("{pid} (test) S {fields} {starttime} 23 24\n")
}

#[derive(Debug, Default)]
struct Source {
    executables: BTreeMap<u32, PathBuf>,
    cmdlines: BTreeMap<u32, Vec<u8>>,
    cgroups: BTreeMap<u32, String>,
    statuses: BTreeMap<u32, String>,
    flatpak_info: BTreeMap<u32, String>,
    security_labels: BTreeMap<u32, String>,
}

impl Source {
    fn with_process(mut self, pid: u32, executable: PathBuf, argv: &[&str], ppid: u32) -> Self {
        self.executables.insert(pid, executable);
        let mut cmdline = argv.join("\0").into_bytes();
        cmdline.push(0);
        self.cmdlines.insert(pid, cmdline);
        self.cgroups.insert(
            pid,
            format!("0::/user.slice/user-1000.slice/session-{pid}.scope\n"),
        );
        self.statuses.insert(
            pid,
            format!("Name:\ttest\nState:\tS (sleeping)\nPPid:\t{ppid}\n"),
        );
        self
    }

    fn with_cgroup(mut self, pid: u32, cgroup: &str) -> Self {
        self.cgroups.insert(pid, format!("0::{cgroup}\n"));
        self
    }

    fn with_flatpak_info(mut self, pid: u32, info: &str) -> Self {
        self.flatpak_info.insert(pid, info.to_owned());
        self
    }

    fn with_security_label(mut self, pid: u32, label: &str) -> Self {
        self.security_labels.insert(pid, label.to_owned());
        self
    }
}

impl LinuxExecutionFactSource for Source {
    fn executable_path(&self, pid: u32) -> io::Result<PathBuf> {
        self.executables
            .get(&pid)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing executable"))
    }

    fn cmdline_bytes(&self, pid: u32) -> io::Result<Vec<u8>> {
        self.cmdlines
            .get(&pid)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing cmdline"))
    }

    fn cgroup_text(&self, pid: u32) -> io::Result<String> {
        self.cgroups
            .get(&pid)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing cgroup"))
    }

    fn status_text(&self, pid: u32) -> io::Result<String> {
        self.statuses
            .get(&pid)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing status"))
    }

    fn stat_text(&self, pid: u32) -> io::Result<String> {
        if self.executables.contains_key(&pid) {
            Ok(stat(pid))
        } else {
            Err(io::Error::new(io::ErrorKind::NotFound, "missing stat"))
        }
    }

    fn flatpak_info(&self, pid: u32) -> io::Result<Option<String>> {
        Ok(self.flatpak_info.get(&pid).cloned())
    }

    fn security_label(&self, pid: u32) -> io::Result<Option<String>> {
        Ok(self.security_labels.get(&pid).cloned())
    }
}

fn empty_classifier() -> ExecutionContextClassifier {
    ExecutionContextClassifier::new(Vec::new())
}

#[test]
fn collector_ignores_package_like_argv_without_kernel_or_namespace_evidence() {
    let dir = fixture_dir();
    let launcher = executable(&dir, "launcher", b"launcher");
    let source = Source::default().with_process(
        100,
        launcher,
        &[
            "/usr/bin/launcher",
            "SNAP_NAME=fake",
            "FLATPAK_ID=org.fake.App",
            "APPIMAGE=/tmp/fake.AppImage",
        ],
        0,
    );

    let observed = collect_execution_observation(&source, 100, &empty_classifier()).unwrap();

    assert_eq!(observed.origin(), ExecutionOrigin::Direct);
    assert!(observed.package().is_none());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn flatpak_id_comes_from_flatpak_info_inside_process_root() {
    let dir = fixture_dir();
    let launcher = executable(&dir, "bwrap", b"flatpak-launcher");
    let source = Source::default()
        .with_process(101, launcher, &["/usr/bin/bwrap"], 0)
        .with_flatpak_info(
            101,
            "[Application]\nname=org.mozilla.firefox\nruntime=org.freedesktop.Platform/x86_64/24.08\n",
        );

    let observed = collect_execution_observation(&source, 101, &empty_classifier()).unwrap();

    assert_eq!(observed.origin(), ExecutionOrigin::Flatpak);
    assert_eq!(
        observed.package(),
        Some(&PackageIdentity::new(
            PackageKind::Flatpak,
            "org.mozilla.firefox"
        ))
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn snap_id_requires_kernel_security_label_in_enforce_mode() {
    let dir = fixture_dir();
    let launcher = executable(&dir, "spotify", b"snap-launcher");
    let enforced = Source::default()
        .with_process(102, launcher.clone(), &["/snap/spotify/current/spotify"], 0)
        .with_security_label(102, "snap.spotify.spotify (enforce)\n");
    let complain = Source::default()
        .with_process(103, launcher, &["/snap/spotify/current/spotify"], 0)
        .with_security_label(103, "snap.spotify.spotify (complain)\n");

    let enforced_observation =
        collect_execution_observation(&enforced, 102, &empty_classifier()).unwrap();
    let complain_observation =
        collect_execution_observation(&complain, 103, &empty_classifier()).unwrap();

    assert_eq!(enforced_observation.origin(), ExecutionOrigin::Snap);
    assert_eq!(
        enforced_observation.package(),
        Some(&PackageIdentity::new(PackageKind::Snap, "spotify"))
    );
    assert!(complain_observation.package().is_none());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unified_cgroup_is_used_for_container_and_user_systemd_context() {
    let dir = fixture_dir();
    let tool = executable(&dir, "tool", b"tool");
    let container = Source::default()
        .with_process(104, tool.clone(), &["/usr/bin/tool"], 0)
        .with_cgroup(104, "/system.slice/docker-abcdef.scope");
    let user_systemd = Source::default()
        .with_process(105, tool, &["/usr/bin/tool"], 0)
        .with_cgroup(
            105,
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-tool.scope",
        );

    assert_eq!(
        collect_execution_observation(&container, 104, &empty_classifier())
            .unwrap()
            .origin(),
        ExecutionOrigin::Container
    );
    assert_eq!(
        collect_execution_observation(&user_systemd, 105, &empty_classifier())
            .unwrap()
            .origin(),
        ExecutionOrigin::UserSystemd
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn parent_is_reobserved_with_stable_identity_before_ide_classification() {
    let dir = fixture_dir();
    let ide = executable(&dir, "renamed-ide", b"trusted-ide-parent");
    let child = executable(&dir, "child", b"child");
    let ide_digest = focus_linux::observe_executable(&ide, ExecutionOrigin::Direct)
        .unwrap()
        .digest()
        .unwrap();
    let classifier = ExecutionContextClassifier::new(vec![ExecutableMatcher::Digest(ide_digest)]);
    let source = Source::default()
        .with_process(200, ide, &["/opt/editor/renamed-ide"], 0)
        .with_process(201, child, &["/home/student/code/child"], 200);

    let observed = collect_execution_observation(&source, 201, &classifier).unwrap();

    assert_eq!(observed.origin(), ExecutionOrigin::IdeChild);
    assert_eq!(observed.parent().unwrap().digest(), Some(ide_digest));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn invalid_cmdline_or_missing_unified_cgroup_fails_closed() {
    let dir = fixture_dir();
    let tool = executable(&dir, "tool", b"tool");
    let mut invalid_utf8 = Source::default().with_process(300, tool.clone(), &["tool"], 0);
    invalid_utf8.cmdlines.insert(300, vec![0xff, 0]);
    let mut legacy_cgroup = Source::default().with_process(301, tool, &["tool"], 0);
    legacy_cgroup
        .cgroups
        .insert(301, "2:cpu:/legacy\n".to_owned());

    assert!(collect_execution_observation(&invalid_utf8, 300, &empty_classifier()).is_err());
    assert!(collect_execution_observation(&legacy_cgroup, 301, &empty_classifier()).is_err());
    fs::remove_dir_all(dir).unwrap();
}
