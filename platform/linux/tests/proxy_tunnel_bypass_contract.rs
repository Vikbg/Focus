use std::{fs, path::PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn task29_requires_real_proxy_and_tunnel_bypass_gate() {
    let root = repo_root();
    let live = fs::read_to_string(root.join("platform/linux/tests/proxy_tunnel_bypass_live.rs"))
        .expect("Task 29 proxy and tunnel bypass live test file is missing");
    let workflow = fs::read_to_string(root.join(".github/workflows/proxy-tunnel-bypass-live.yml"))
        .expect("Task 29 proxy and tunnel bypass live CI workflow is missing");

    for marker in [
        "ProductionNetworkGuard",
        "curl",
        "--proxy",
        "--socks5-hostname",
        "\"-D\"",
        "dig",
        "tor_like",
        "arm()",
        "verify()",
        "disarm()",
        "proxy-tunnel-bypass-live",
    ] {
        assert!(
            live.contains(marker),
            "proxy and tunnel bypass live test is missing {marker}"
        );
    }

    for marker in [
        "name: Proxy and tunnel bypass live",
        "runs-on: ubuntu-24.04",
        "systemd-detect-virt --vm",
        "dnsutils",
        "openssh-server",
        "netcat-openbsd",
        "--test proxy_tunnel_bypass_live",
        "--ignored",
        "--nocapture",
    ] {
        assert!(
            workflow.contains(marker),
            "proxy and tunnel bypass live workflow is missing {marker}"
        );
    }
}
