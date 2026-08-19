use std::{
    env, fs,
    io::Write,
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
};

use focus_linux::{
    CgroupEgressPolicy, EgressProtocol, ExecutionContextClassifier, FOCUS_CGROUP_ROOT,
    FOCUS_EBPF_OBJECT_PATH, FocusCgroupClass, FocusCgroupControl, Ipv4EgressRule,
    ProcfsExecutionFactSource, SystemCgroupControl, SystemEgressClassProgramControl,
    arm_cgroup_egress_programs, collect_running_process,
};

const SCENARIO: &str = "ebpf-egress-live";
const CLASS_NAMES: [&str; 5] = ["browser", "development", "vpn", "system", "blocked"];

fn remove_focus_tree_best_effort() {
    for name in CLASS_NAMES {
        let _ = fs::remove_dir(Path::new(FOCUS_CGROUP_ROOT).join(name));
    }
    let _ = fs::remove_dir(FOCUS_CGROUP_ROOT);
}

struct FocusCgroupCleanup;

impl Drop for FocusCgroupCleanup {
    fn drop(&mut self) {
        remove_focus_tree_best_effort();
    }
}

struct ProbeChild {
    child: Child,
    trigger: Option<ChildStdin>,
}

impl ProbeChild {
    fn waiting_for_tcp_probe(port: u16) -> Self {
        let mut child = Command::new("/bin/sh")
            .args([
                "-c",
                "read -r _; exec /usr/bin/nc -z -w 1 127.0.0.1 \"$FOCUS_PROBE_PORT\"",
            ])
            .env("FOCUS_PROBE_PORT", port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("network probe fixture must start");
        let trigger = child
            .stdin
            .take()
            .expect("network probe fixture must expose stdin");
        Self {
            child,
            trigger: Some(trigger),
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn release_and_wait(mut self) -> bool {
        let mut trigger = self
            .trigger
            .take()
            .expect("network probe trigger must still be available");
        trigger
            .write_all(b"go\n")
            .expect("network probe must be releasable");
        drop(trigger);
        self.child
            .wait()
            .expect("network probe must produce an exit status")
            .success()
    }
}

fn bind_tcp_fixture() -> TcpListener {
    TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("local TCP fixture must bind")
}

fn rule_for(listener: &TcpListener) -> Ipv4EgressRule {
    let address = listener
        .local_addr()
        .expect("local TCP fixture address must be readable");
    let port = match address {
        std::net::SocketAddr::V4(address) => address.port(),
        std::net::SocketAddr::V6(_) => panic!("Task 27 live fixture must bind IPv4 loopback"),
    };
    Ipv4EgressRule::new(Ipv4Addr::LOCALHOST, port, EgressProtocol::Tcp)
        .expect("fixture endpoint must be a valid exact TCP rule")
}

fn probe_from_class(class: FocusCgroupClass, port: u16, cgroups: &mut SystemCgroupControl) -> bool {
    let probe = ProbeChild::waiting_for_tcp_probe(port);
    let classifier = ExecutionContextClassifier::new(Vec::new());
    let process = collect_running_process(&ProcfsExecutionFactSource, probe.pid(), &classifier)
        .expect("network probe process must be observable before release");
    let lifetime = process.lifetime();

    cgroups
        .place_process(class, lifetime)
        .expect("network probe must enter its exact Focus cgroup class");
    cgroups
        .verify_process(class, lifetime)
        .expect("network probe cgroup placement must verify before release");

    probe.release_and_wait()
}

#[test]
#[ignore = "requires disposable root VM with writable cgroup v2, eBPF, and netcat"]
fn per_class_ebpf_egress_allows_exact_rules_and_denies_everything_else() {
    assert_eq!(env::var("FOCUS_VM_SCENARIO").as_deref(), Ok(SCENARIO));
    assert!(
        Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
        "cgroup v2 controller file must exist"
    );
    assert!(
        Path::new(FOCUS_EBPF_OBJECT_PATH).is_file(),
        "installed Task 27 eBPF object must exist"
    );
    assert!(
        !Path::new(FOCUS_CGROUP_ROOT).exists(),
        "disposable VM must start without pre-existing Focus cgroup state"
    );

    let uid = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .expect("fixture uid must be queryable");
    assert!(uid.status.success());
    assert_eq!(String::from_utf8_lossy(&uid.stdout).trim(), "0");

    let _cleanup = FocusCgroupCleanup;
    let browser_server = bind_tcp_fixture();
    let development_server = bind_tcp_fixture();
    let browser_rule = rule_for(&browser_server);
    let development_rule = rule_for(&development_server);
    let browser_port = browser_rule.port();
    let development_port = development_rule.port();

    let policy = CgroupEgressPolicy::new(
        vec![browser_rule],
        vec![development_rule],
        Vec::new(),
        Vec::new(),
    );
    let mut cgroups = SystemCgroupControl;
    cgroups
        .prepare_classes()
        .expect("fixed Focus cgroup classes must be prepared");

    let mut programs = SystemEgressClassProgramControl::default();
    arm_cgroup_egress_programs(&mut programs, &policy)
        .expect("all five fixed cgroup eBPF programs must arm and verify");

    assert!(
        probe_from_class(FocusCgroupClass::Browser, browser_port, &mut cgroups),
        "browser class must reach its exact allowed endpoint"
    );
    assert!(
        !probe_from_class(
            FocusCgroupClass::Browser,
            development_port,
            &mut cgroups
        ),
        "browser class must not inherit the development endpoint"
    );
    assert!(
        probe_from_class(
            FocusCgroupClass::Development,
            development_port,
            &mut cgroups
        ),
        "development class must reach its exact allowed endpoint"
    );
    assert!(
        !probe_from_class(FocusCgroupClass::Development, browser_port, &mut cgroups),
        "development class must not inherit the browser endpoint"
    );
    assert!(
        !probe_from_class(FocusCgroupClass::Vpn, browser_port, &mut cgroups),
        "empty vpn rules must remain default-deny"
    );
    assert!(
        !probe_from_class(FocusCgroupClass::Blocked, browser_port, &mut cgroups),
        "blocked class must remain structurally default-deny"
    );

    drop(programs);
    remove_focus_tree_best_effort();
    assert!(
        !Path::new(FOCUS_CGROUP_ROOT).exists(),
        "Focus cgroup tree must be removable after eBPF links are dropped"
    );
}
