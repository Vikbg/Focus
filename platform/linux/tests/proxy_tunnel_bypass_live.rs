use std::{
    env, fs,
    io::{self, ErrorKind, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use focus_linux::{NetworkGuardControl, ProductionNetworkGuard};

const NFT_CANDIDATES: [&str; 2] = ["/usr/sbin/nft", "/usr/bin/nft"];
const SSHD_CANDIDATES: [&str; 2] = ["/usr/sbin/sshd", "/usr/bin/sshd"];

fn nft_executable() -> &'static str {
    NFT_CANDIDATES
        .into_iter()
        .find(|candidate| Path::new(candidate).is_file())
        .expect("Task 29 live fixture requires nft")
}

fn sshd_executable() -> &'static str {
    SSHD_CANDIDATES
        .into_iter()
        .find(|candidate| Path::new(candidate).is_file())
        .expect("Task 29 live fixture requires sshd")
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

fn loopback_listener() -> TcpListener {
    TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("failed to bind loopback fixture")
}

fn relay_bidirectional(mut client: TcpStream, mut upstream: TcpStream) {
    let Ok(mut client_reader) = client.try_clone() else {
        return;
    };
    let Ok(mut upstream_writer) = upstream.try_clone() else {
        return;
    };
    let client_to_upstream = thread::spawn(move || {
        let _ = io::copy(&mut client_reader, &mut upstream_writer);
    });
    let _ = io::copy(&mut upstream, &mut client);
    let _ = client_to_upstream.join();
}

struct TcpFixture {
    address: SocketAddrV4,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl TcpFixture {
    fn start<F>(handler: F) -> Self
    where
        F: Fn(TcpStream) + Send + Sync + 'static,
    {
        let listener = loopback_listener();
        let address = match listener.local_addr().expect("failed to read fixture address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => panic!("Task 29 fixtures must bind IPv4 loopback"),
        };
        listener
            .set_nonblocking(true)
            .expect("failed to configure loopback fixture");
        let handler = Arc::new(handler);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker_handler = Arc::clone(&handler);
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let handler = Arc::clone(&worker_handler);
                        thread::spawn(move || handler(stream));
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

    fn address(&self) -> SocketAddrV4 {
        self.address
    }

    fn url(&self) -> String {
        format!("http://{}:{}/", self.address.ip(), self.address.port())
    }
}

impl Drop for TcpFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("TCP fixture thread panicked");
        }
    }
}

fn start_http_target() -> TcpFixture {
    TcpFixture::start(|mut stream| {
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request);
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
        );
    })
}

fn read_http_headers(stream: &mut TcpStream) -> io::Result<()> {
    let mut data = Vec::new();
    let mut byte = [0_u8; 1];
    while data.len() < 16 * 1024 {
        stream.read_exact(&mut byte)?;
        data.push(byte[0]);
        if data.ends_with(b"\r\n\r\n") {
            return Ok(());
        }
    }
    Err(io::Error::new(
        ErrorKind::InvalidData,
        "HTTP proxy request headers are too large",
    ))
}

fn start_http_proxy(target: SocketAddrV4) -> TcpFixture {
    TcpFixture::start(move |mut client| {
        if read_http_headers(&mut client).is_err() {
            return;
        }
        let Ok(mut upstream) = TcpStream::connect(target) else {
            return;
        };
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
            target.ip(),
            target.port()
        );
        if upstream.write_all(request.as_bytes()).is_err() {
            return;
        }
        let _ = io::copy(&mut upstream, &mut client);
    })
}

fn consume_socks_destination(client: &mut TcpStream, atyp: u8) -> io::Result<()> {
    match atyp {
        1 => {
            let mut address = [0_u8; 4];
            client.read_exact(&mut address)?;
        }
        3 => {
            let mut length = [0_u8; 1];
            client.read_exact(&mut length)?;
            let mut domain = vec![0_u8; usize::from(length[0])];
            client.read_exact(&mut domain)?;
        }
        4 => {
            let mut address = [0_u8; 16];
            client.read_exact(&mut address)?;
        }
        _ => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "unsupported SOCKS address type",
            ));
        }
    }
    let mut port = [0_u8; 2];
    client.read_exact(&mut port)
}

fn start_socks5_proxy(target: SocketAddrV4) -> TcpFixture {
    TcpFixture::start(move |mut client| {
        let mut greeting = [0_u8; 2];
        if client.read_exact(&mut greeting).is_err() || greeting[0] != 5 {
            return;
        }
        let mut methods = vec![0_u8; usize::from(greeting[1])];
        if client.read_exact(&mut methods).is_err() || client.write_all(&[5, 0]).is_err() {
            return;
        }

        let mut request = [0_u8; 4];
        if client.read_exact(&mut request).is_err() || request[0] != 5 || request[1] != 1 {
            return;
        }
        if consume_socks_destination(&mut client, request[3]).is_err() {
            return;
        }
        let Ok(upstream) = TcpStream::connect(target) else {
            let _ = client.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
            return;
        };
        if client
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .is_err()
        {
            return;
        }
        relay_bidirectional(client, upstream);
    })
}

fn start_tor_like_relay(target: SocketAddrV4) -> TcpFixture {
    TcpFixture::start(move |client| {
        if let Ok(upstream) = TcpStream::connect(target) {
            relay_bidirectional(client, upstream);
        }
    })
}

struct DnsFixture {
    address: SocketAddrV4,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

fn dns_question_end(packet: &[u8]) -> Option<usize> {
    let mut offset = 12;
    while offset < packet.len() {
        let length = usize::from(*packet.get(offset)?);
        offset += 1;
        if length == 0 {
            return (offset + 4 <= packet.len()).then_some(offset + 4);
        }
        offset = offset.checked_add(length)?;
    }
    None
}

fn dns_answer(packet: &[u8]) -> Option<Vec<u8>> {
    let question_end = dns_question_end(packet)?;
    let mut response = Vec::with_capacity(question_end + 16);
    response.extend_from_slice(packet.get(0..2)?);
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&[0x00, 0x01]);
    response.extend_from_slice(&[0x00, 0x01]);
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    response.extend_from_slice(packet.get(12..question_end)?);
    response.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 203, 0,
        113, 53,
    ]);
    Some(response)
}

impl DnsFixture {
    fn start() -> Self {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("failed to bind DNS fixture");
        let address = match socket.local_addr().expect("failed to read DNS fixture address") {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => panic!("Task 29 DNS fixture must bind IPv4 loopback"),
        };
        socket
            .set_nonblocking(true)
            .expect("failed to configure DNS fixture");
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut packet = [0_u8; 4096];
            while !worker_stop.load(Ordering::Acquire) {
                match socket.recv_from(&mut packet) {
                    Ok((length, peer)) => {
                        if let Some(response) = dns_answer(&packet[..length]) {
                            let _ = socket.send_to(&response, peer);
                        }
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

    fn port(&self) -> String {
        self.address.port().to_string()
    }
}

impl Drop for DnsFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("DNS fixture thread panicked");
        }
    }
}

fn unused_tcp_port() -> u16 {
    loopback_listener()
        .local_addr()
        .expect("failed to allocate fixture port")
        .port()
}

fn wait_for_tcp_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("fixture port {port} did not become reachable");
}

struct SshDynamicFixture {
    directory: PathBuf,
    dynamic_port: u16,
    ssh: Child,
    sshd: Child,
}

impl SshDynamicFixture {
    fn start() -> Self {
        let directory = env::temp_dir().join(format!("focus-task29-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("failed to create SSH fixture directory");

        let host_key = directory.join("host_key");
        let client_key = directory.join("client_key");
        for key in [&host_key, &client_key] {
            let status = Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(key)
                .status()
                .expect("failed to run ssh-keygen");
            assert!(status.success(), "ssh-keygen failed");
        }
        fs::copy(client_key.with_extension("pub"), directory.join("authorized_keys"))
            .expect("failed to create authorized_keys");

        let ssh_port = unused_tcp_port();
        let dynamic_port = unused_tcp_port();
        let config = directory.join("sshd_config");
        fs::write(
            &config,
            format!(
                "Port {ssh_port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}/sshd.pid\nAuthorizedKeysFile {}/authorized_keys\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\nUsePAM no\nAllowTcpForwarding yes\nStrictModes no\nLogLevel QUIET\n",
                host_key.display(),
                directory.display(),
                directory.display()
            ),
        )
        .expect("failed to write sshd fixture config");

        let sshd = Command::new(sshd_executable())
            .args(["-D", "-e", "-f"])
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to start sshd fixture");
        wait_for_tcp_port(ssh_port);

        let ssh = Command::new("ssh")
            .args([
                "-N",
                "-D",
                &format!("127.0.0.1:{dynamic_port}"),
                "-p",
                &ssh_port.to_string(),
                "-i",
            ])
            .arg(&client_key)
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "root@127.0.0.1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to start ssh -D fixture");
        wait_for_tcp_port(dynamic_port);

        Self {
            directory,
            dynamic_port,
            ssh,
            sshd,
        }
    }
}

impl Drop for SshDynamicFixture {
    fn drop(&mut self) {
        let _ = self.ssh.kill();
        let _ = self.ssh.wait();
        let _ = self.sshd.kill();
        let _ = self.sshd.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn curl_status(args: &[String]) -> bool {
    let mut command = Command::new("curl");
    command.args([
        "--fail",
        "--silent",
        "--show-error",
        "--noproxy",
        "",
        "--connect-timeout",
        "1",
        "--max-time",
        "2",
    ]);
    command.args(args);
    command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn http_proxy_succeeds(proxy: &TcpFixture, target_url: &str) -> bool {
    curl_status(&[
        "--proxy".to_string(),
        format!("http://{}", proxy.address()),
        target_url.to_string(),
    ])
}

fn socks_proxy_succeeds(proxy_port: u16, target_url: &str) -> bool {
    curl_status(&[
        "--socks5-hostname".to_string(),
        format!("127.0.0.1:{proxy_port}"),
        target_url.to_string(),
    ])
}

fn alternate_dns_succeeds(dns: &DnsFixture) -> bool {
    Command::new("dig")
        .args([
            "+time=1",
            "+tries=1",
            "+short",
            "@127.0.0.1",
            "-p",
            &dns.port(),
            "focus.test",
            "A",
        ])
        .output()
        .is_ok_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).trim() == "203.0.113.53"
        })
}

fn tor_like_relay_succeeds(relay: &TcpFixture) -> bool {
    curl_status(&[relay.url()])
}

fn assert_all_bypasses_reachable(
    target: &TcpFixture,
    http_proxy: &TcpFixture,
    socks_proxy: &TcpFixture,
    ssh_dynamic: &SshDynamicFixture,
    dns: &DnsFixture,
    tor_like: &TcpFixture,
) {
    let target_url = target.url();
    assert!(
        http_proxy_succeeds(http_proxy, &target_url),
        "HTTP proxy fixture is not reachable before protection"
    );
    assert!(
        socks_proxy_succeeds(socks_proxy.address().port(), &target_url),
        "SOCKS proxy fixture is not reachable before protection"
    );
    assert!(
        socks_proxy_succeeds(ssh_dynamic.dynamic_port, &target_url),
        "ssh -D fixture is not reachable before protection"
    );
    assert!(
        alternate_dns_succeeds(dns),
        "alternate DNS fixture is not reachable before protection"
    );
    assert!(
        tor_like_relay_succeeds(tor_like),
        "Tor-like relay fixture is not reachable before protection"
    );
}

fn assert_all_bypasses_blocked(
    target: &TcpFixture,
    http_proxy: &TcpFixture,
    socks_proxy: &TcpFixture,
    ssh_dynamic: &SshDynamicFixture,
    dns: &DnsFixture,
    tor_like: &TcpFixture,
) {
    let target_url = target.url();
    assert!(
        !http_proxy_succeeds(http_proxy, &target_url),
        "HTTP proxy bypassed strict outbound protection"
    );
    assert!(
        !socks_proxy_succeeds(socks_proxy.address().port(), &target_url),
        "SOCKS proxy bypassed strict outbound protection"
    );
    assert!(
        !socks_proxy_succeeds(ssh_dynamic.dynamic_port, &target_url),
        "ssh -D bypassed strict outbound protection"
    );
    assert!(
        !alternate_dns_succeeds(dns),
        "alternate DNS bypassed strict outbound protection"
    );
    assert!(
        !tor_like_relay_succeeds(tor_like),
        "Tor-like relay bypassed strict outbound protection"
    );
}

#[test]
#[ignore = "requires disposable root VM with nftables, proxy fixtures, DNS, and OpenSSH"]
fn strict_guard_blocks_unapproved_proxy_and_tunnel_paths() {
    assert_eq!(
        env::var("FOCUS_VM_SCENARIO").as_deref(),
        Ok("proxy-tunnel-bypass-live")
    );

    let uid = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .expect("failed to query fixture uid");
    assert!(uid.status.success());
    assert_eq!(String::from_utf8_lossy(&uid.stdout).trim(), "0");

    let _cleanup = FocusTableCleanup;
    remove_focus_table();

    let target = start_http_target();
    let http_proxy = start_http_proxy(target.address());
    let socks_proxy = start_socks5_proxy(target.address());
    let tor_like = start_tor_like_relay(target.address());
    let dns = DnsFixture::start();
    let ssh_dynamic = SshDynamicFixture::start();

    assert_all_bypasses_reachable(
        &target,
        &http_proxy,
        &socks_proxy,
        &ssh_dynamic,
        &dns,
        &tor_like,
    );

    let mut guard = ProductionNetworkGuard::default();
    guard.arm().expect("strict outbound arm failed");
    guard.verify().expect("strict outbound verification failed");
    assert_all_bypasses_blocked(
        &target,
        &http_proxy,
        &socks_proxy,
        &ssh_dynamic,
        &dns,
        &tor_like,
    );

    guard.disarm().expect("strict outbound disarm failed");
    assert_all_bypasses_reachable(
        &target,
        &http_proxy,
        &socks_proxy,
        &ssh_dynamic,
        &dns,
        &tor_like,
    );
}
