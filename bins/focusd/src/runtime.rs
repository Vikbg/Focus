use std::{
    fs,
    future::Future,
    io,
    path::Path,
    sync::{Arc, RwLock},
};

use focus_platform::PlatformBackend;
use focus_protocol::{
    ClientKind, Request, RequestEnvelope, RequestId, Response, ResponseEnvelope, ResponseError,
};
use focus_storage::FocusStore;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
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
    let mut request = String::new();
    let read = {
        let mut reader = BufReader::new(&mut *stream);
        timeout(IPC_READ_TIMEOUT, reader.read_line(&mut request)).await
    };

    match read {
        Ok(Ok(_)) => match RequestEnvelope::decode(request.trim()) {
            Ok(envelope) => Ok(Ok(envelope)),
            Err(_) => Ok(Err(ResponseError::InvalidRequest)),
        },
        Ok(Err(error)) => Err(error),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "authenticated IPC peer exceeded the read timeout",
        )),
    }
}

const fn is_read_only(request: Request) -> bool {
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

async fn serve_connection<S, B>(
    mut stream: UnixStream,
    service: Arc<Mutex<DaemonService<S, B>>>,
    snapshot: Arc<RwLock<DaemonSnapshot>>,
    policy: PeerPolicy,
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
    if !envelope.is_authorized_as(ClientKind::Cli) {
        return write_response(
            &mut stream,
            envelope.request_id(),
            Response::Error(ResponseError::Unauthorized),
        )
        .await;
    }

    let request = envelope.request();
    let response = if is_read_only(request) {
        response_for(request, snapshot_state(&snapshot))
    } else {
        service.lock().await.handle(request).await
    };

    write_response(&mut stream, envelope.request_id(), response).await
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
        listener.set_nonblocking(true)?;
        let listener = UnixListener::from_std(listener)?;
        let mut connections = JoinSet::new();
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                _ = &mut shutdown => break,
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
        let _ = fs::remove_file(socket_path);
        Ok(())
    }
}
