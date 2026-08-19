use std::{
    env,
    io::{ErrorKind, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use focus_linux::{NetworkGuardControl, ProductionNetworkGuard};

const NFT_CANDIDATES: [&str; 2] = ["/usr/sbin/nft", "/usr/bin/nft"];

fn nft_executable() -> &'static str {
    NFT_CANDIDATES
        .into_iter()
        .find(|candidate| Path::new(candidate).is_file())
        .expect("Task 25 live fixture requires nft")
}

fn remove_focus_table() {
    let _ = Command::new(nft_executable())
        .args(["destroy", "table", "inet", "focus"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

struct FocusTableCleanup;

impl Drop for FocusTableCleanup {
    fn drop(&mut self) {
        remove_focus_table();
    }
}

struct LocalHttpServer {
    address: SocketAddrV4,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl LocalHttpServer {
    fn start() -> Self {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("failed to bind local HTTP fixture");
        let address = match listener
            .local_addr()
            .expect("failed to read fixture address")
        {
            std::net::SocketAddr::V4(address) => address,
            std::net::SocketAddr::V6(_) => panic!("Task 25 fixture must bind IPv4 loopback"),
        };
        listener
            .set_nonblocking(true)
            .expect("failed to configure local HTTP fixture");

        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        );
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }

    fn url(&self) -> String {
        format!("http://{}:{}/", self.address.ip(), self.address.port())
    }

    fn port(&self) -> String {
        self.address.port().to_string()
    }
}

impl Drop for LocalHttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("local HTTP fixture thread panicked");
        }
    }
}

fn curl_succeeds(url: &str) -> bool {
    Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "1",
            "--max-time",
            "2",
            url,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn wget_succeeds(url: &str) -> bool {
    Command::new("wget")
        .args(["--quiet", "--timeout=1", "--tries=1", "-O", "-", url])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn nc_succeeds(port: &str) -> bool {
    Command::new("nc")
        .args(["-z", "-w", "1", "127.0.0.1", port])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn assert_all_paths_reachable(server: &LocalHttpServer) {
    let url = server.url();
    let port = server.port();
    assert!(curl_succeeds(&url), "curl fixture is not reachable");
    assert!(wget_succeeds(&url), "wget fixture is not reachable");
    assert!(nc_succeeds(&port), "nc fixture is not reachable");
}

fn assert_all_paths_blocked(server: &LocalHttpServer) {
    let url = server.url();
    let port = server.port();
    assert!(
        !curl_succeeds(&url),
        "curl bypassed strict outbound baseline"
    );
    assert!(
        !wget_succeeds(&url),
        "wget bypassed strict outbound baseline"
    );
    assert!(!nc_succeeds(&port), "nc bypassed strict outbound baseline");
}

#[test]
#[ignore = "requires disposable root VM with nftables, curl, wget, and netcat"]
fn strict_outbound_guard_blocks_unknown_curl_wget_and_nc_paths() {
    assert_eq!(
        env::var("FOCUS_VM_SCENARIO").as_deref(),
        Ok("strict-outbound-live")
    );

    let uid = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .expect("failed to query fixture uid");
    assert!(uid.status.success());
    assert_eq!(String::from_utf8_lossy(&uid.stdout).trim(), "0");

    let _cleanup = FocusTableCleanup;
    remove_focus_table();
    let server = LocalHttpServer::start();

    assert_all_paths_reachable(&server);

    let mut guard = ProductionNetworkGuard::default();
    guard.arm().expect("strict outbound arm failed");
    guard.verify().expect("strict outbound verification failed");
    assert_all_paths_blocked(&server);

    guard.disarm().expect("strict outbound disarm failed");
    assert_all_paths_reachable(&server);
}
