use std::{
    fs,
    future::Future,
    io,
    path::Path,
    sync::{Arc, RwLock},
};

use focus_platform::PlatformBackend;
use focus_protocol::{
    ClientKind, MAX_FRAME_BYTES, Request, RequestEnvelope, RequestId, Response, ResponseEnvelope,
    ResponseError,
};
use focus_storage::FocusStore;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Mutex,
    task::JoinSet,
    time::timeout,
};

use crate::{
    DaemonService, DaemonSnapshot, IPC_READ_TIMEOUT, PeerPolicy, bind_production_socket,
    response_for,
};

fn authenticate_peer(policy: &PeerPolicy, stream: &UnixStream) -> bool {
    let Ok(credentials) = getsockopt(stream, PeerCredentials) else {
        return false;
    };
    if credentials.uid() != policy.allowed_uid || credentials.pid() <= 0 {
        return false;
    }

    let peer_executable = std::path::PathBuf::from(format!("/proc/{}/exe", credentials.pid()));
    let Ok(peer_executable) = fs::read_link(peer_executable) else {
        return false;
    };
    let Ok(peer_executable) = fs::canonicalize(peer_executable) else {
        return false;
    };
    let Ok(expected_executable) = fs::canonicalize(&policy.cli_executable) else {
        return false;
    };

    peer_executable == expected_executable
}

async fn write_response(
    stream: &mut UnixStream,
    request_id: RequestId,
    response: Response,
) -> io::Result<()> {
    let envelope = ResponseEnvelope::new(request_id, response);
    stream.write_all(envelope.encode().as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await
}

async fn read_request(
    stream: &mut UnixStream,
) -> io::Result<Result<RequestEnvelope, ResponseError>> {
    let operation = async {
        let mut frame = Vec::with_capacity(1024);
        let mut chunk = [0_u8; 1024];

        loop {
            let count = stream.read(&mut chunk).await?;
            if count == 0 {
                return Ok(Err(ResponseError::InvalidRequest));
            }

            let received = &chunk[..count];
            if let Some(newline) = received.iter().position(|byte| *byte == b'\n') {
                if frame.len() + newline > MAX_FRAME_BYTES {
                    return Ok(Err(ResponseError::InvalidRequest));
                }
                frame.extend_from_slice(&received[..newline]);
                let Ok(line) = std::str::from_utf8(&frame) else {
                    return Ok(Err(ResponseError::InvalidRequest));
                };
                return Ok(RequestEnvelope::decode(line).map_err(|_| ResponseError::InvalidRequest));
            }

            if frame.len() + count > MAX_FRAME_BYTES {
                return Ok(Err(ResponseError::InvalidRequest));
            }
            frame.extend_from_slice(received);
        }
    };

    match timeout(IPC_READ_TIMEOUT, operation).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "authenticated IPC peer exceeded the read timeout",
        )),
    }
}

const fn is_read_only(request: &Request) -> bool {
    matches!(
        request,
        Request::GetStatus
            | Request::GetSession
            | Request::GetProfiles
            | Request::Doctor
            | Request::GetVpnList
    )
}

fn snapshot_state(snapshot: &Arc<RwLock<DaemonSnapshot>>) -> crate::DaemonState {
    snapshot
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .state()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

impl SocketIdentity {
    fn capture(path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bound IPC path is not a Unix socket",
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn remove_if_unchanged(self, path: &Path) -> io::Result<()> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };

        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            fs::remove_file(path)?;
        }
        Ok(())
    }
}

async fn serve_connection<S, B>(
    stream: UnixStream,
    service: Arc<Mutex<DaemonService<S, B>>>,
    snapshot: Arc<RwLock<DaemonSnapshot>>,
    policy: PeerPolicy,
) -> io::Result<()>
where
    S: FocusStore + Send + 'static,
    B: PlatformBackend + Send + 'static,
{
    serve_connection_as(stream, service, snapshot, policy, ClientKind::Cli).await
}

async fn serve_connection_as<S, B>(
    mut stream: UnixStream,
    service: Arc<Mutex<DaemonService<S, B>>>,
    snapshot: Arc<RwLock<DaemonSnapshot>>,
    policy: PeerPolicy,
    authenticated_client: ClientKind,
) -> io::Result<()>
where
    S: FocusStore + Send + 'static,
    B: PlatformBackend + Send + 'static,
{
    if !authenticate_peer(&policy, &stream) {
        return write_response(
            &mut stream,
            RequestId(0),
            Response::Error(ResponseError::PeerAuthenticationFailed),
        )
        .await;
    }

    let envelope = match read_request(&mut stream).await? {
        Ok(envelope) => envelope,
        Err(error) => {
            return write_response(&mut stream, RequestId(0), Response::Error(error)).await;
        }
    };

    if !envelope.is_compatible() {
        return write_response(
            &mut stream,
            envelope.request_id(),
            Response::Error(ResponseError::UnsupportedProtocolVersion),
        )
        .await;
    }
    if !envelope.is_authorized_as(authenticated_client) {
        return write_response(
            &mut stream,
            envelope.request_id(),
            Response::Error(ResponseError::Unauthorized),
        )
        .await;
    }

    let request_id = envelope.request_id();
    let request = envelope.into_request();
    let response = if is_read_only(&request) {
        response_for(&request, snapshot_state(&snapshot))
    } else {
        service.lock().await.handle(request_id, request)
    };

    write_response(&mut stream, request_id, response).await
}

/// Concurrent production runtime around the single authoritative daemon service.
pub struct DaemonRuntime<S, B>
where
    S: FocusStore + Send + 'static,
    B: PlatformBackend + Send + 'static,
{
    service: Arc<Mutex<DaemonService<S, B>>>,
    snapshot: Arc<RwLock<DaemonSnapshot>>,
}

impl<S, B> DaemonRuntime<S, B>
where
    S: FocusStore + Send + 'static,
    B: PlatformBackend + Send + 'static,
{
    #[must_use]
    pub fn new(service: DaemonService<S, B>) -> Self {
        let snapshot = service.snapshot_handle();
        Self {
            service: Arc::new(Mutex::new(service)),
            snapshot,
        }
    }

    /// Returns the latest immutable state projection without taking the mutation lock.
    #[must_use]
    pub fn snapshot(&self) -> DaemonSnapshot {
        *self
            .snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Serves authenticated connections concurrently until the shutdown future resolves.
    ///
    /// Security mutations are serialized through one [`DaemonService`] mutex while
    /// read-only requests use the atomically published immutable snapshot.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the production socket cannot be created, configured,
    /// converted to Tokio, or accepted.
    pub async fn serve_until<F>(
        &self,
        socket_path: &Path,
        policy: &PeerPolicy,
        shutdown: F,
    ) -> io::Result<()>
    where
        F: Future<Output = ()>,
    {
        let listener = bind_production_socket(socket_path, policy)?;
        let socket_identity = SocketIdentity::capture(socket_path)?;
        listener.set_nonblocking(true)?;
        let listener = UnixListener::from_std(listener)?;
        let mut connections = JoinSet::new();
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    let service = Arc::clone(&self.service);
                    let snapshot = Arc::clone(&self.snapshot);
                    let policy = policy.clone();
                    connections.spawn(async move {
                        let _ = serve_connection(stream, service, snapshot, policy).await;
                    });
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    let _ = completed;
                }
            }
        }

        drop(listener);
        while connections.join_next().await.is_some() {}
        socket_identity.remove_if_unchanged(socket_path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream as StdUnixStream;

    use focus_core::{
        Decision, PolicySet, PolicyVersion, Profile, ProfileId, RecoveryCodeHash, SessionId,
        SessionState,
    };
    use focus_platform::FakeBackend;
    use focus_protocol::{EmergencyRequestPayload, ProtocolState};
    use focus_storage::{SqliteStore, StoredActiveSession};

    const CODE: &str = "FG7K-P29M-4TXQ-R8VN";

    fn locked_session() -> StoredActiveSession {
        StoredActiveSession::new(
            SessionId(0x701),
            SessionState::Locked,
            Profile::new(
                ProfileId(7),
                PolicyVersion(3),
                PolicySet::new(Decision::Allow),
            )
            .snapshot(),
            1_000,
            2_000,
            RecoveryCodeHash::from_code(CODE),
        )
    }

    fn stream_pair() -> (UnixStream, UnixStream) {
        let (server, client) = StdUnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        client.set_nonblocking(true).unwrap();
        (
            UnixStream::from_std(server).unwrap(),
            UnixStream::from_std(client).unwrap(),
        )
    }

    async fn exchange(mut client: UnixStream, envelope: RequestEnvelope) -> Response {
        client
            .write_all(envelope.encode().as_bytes())
            .await
            .unwrap();
        client.write_all(b"\n").await.unwrap();
        client.flush().await.unwrap();

        let mut frame = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            let count = client.read(&mut byte).await.unwrap();
            assert_ne!(count, 0, "server closed before returning a response");
            if byte[0] == b'\n' {
                break;
            }
            frame.push(byte[0]);
        }
        let line = std::str::from_utf8(&frame).unwrap();
        ResponseEnvelope::decode(line).unwrap().response()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn second_connection_observes_state_mutation() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        store.set_active_session(&locked_session()).unwrap();
        let mut daemon = DaemonService::new(store, FakeBackend::default());
        assert_eq!(daemon.recover().await.unwrap(), SessionState::Locked);

        let snapshot = daemon.snapshot_handle();
        let service = Arc::new(Mutex::new(daemon));
        let policy = PeerPolicy::new(
            nix::unistd::geteuid().as_raw(),
            std::env::current_exe().unwrap(),
        );

        let (first_server, first_client) = stream_pair();
        let first_task = tokio::spawn(serve_connection_as(
            first_server,
            Arc::clone(&service),
            Arc::clone(&snapshot),
            policy.clone(),
            ClientKind::Desktop,
        ));
        let first_response = exchange(
            first_client,
            RequestEnvelope::new(
                RequestId(701),
                ClientKind::Desktop,
                Request::RequestEmergencyUnlock(EmergencyRequestPayload {
                    reason: "runtime live-state regression".to_owned(),
                }),
            ),
        )
        .await;
        first_task.await.unwrap().unwrap();
        assert_eq!(
            first_response,
            Response::Session(ProtocolState::EmergencyPending)
        );

        let (second_server, second_client) = stream_pair();
        let second_task = tokio::spawn(serve_connection_as(
            second_server,
            service,
            snapshot,
            policy,
            ClientKind::Desktop,
        ));
        let second_response = exchange(
            second_client,
            RequestEnvelope::new(RequestId(702), ClientKind::Desktop, Request::GetStatus),
        )
        .await;
        second_task.await.unwrap().unwrap();
        assert_eq!(
            second_response,
            Response::Status(ProtocolState::EmergencyPending)
        );
    }
}
