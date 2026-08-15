use std::{
    env,
    error::Error,
    fs,
    future::Future,
    path::{Path, PathBuf},
    pin::pin,
    task::{Context, Poll, Waker},
};

use focus_platform::FailClosedBackend;
use focus_storage::SqliteStore;
use focusd::{PeerPolicy, recover_session, serve_forever};

const DEFAULT_DB_PATH: &str = "/var/lib/focus/focus.db";
const DEFAULT_SOCKET_PATH: &str = "/run/focus/focusd.sock";
const DEFAULT_CLI_PATH: &str = "/usr/bin/focusctl";

fn main() {
    if let Err(error) = run() {
        eprintln!("focusd: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let database_path =
        PathBuf::from(env::var("FOCUS_DB_PATH").unwrap_or_else(|_| DEFAULT_DB_PATH.to_owned()));
    let socket_path = PathBuf::from(
        env::var("FOCUS_SOCKET_PATH").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_owned()),
    );
    let cli_path =
        PathBuf::from(env::var("FOCUS_CLI_PATH").unwrap_or_else(|_| DEFAULT_CLI_PATH.to_owned()));
    let allowed_uid = match env::var("FOCUS_ALLOWED_UID") {
        Ok(value) => value.parse::<u32>()?,
        Err(_) => nix::unistd::geteuid().as_raw(),
    };

    create_parent(&database_path)?;
    let mut store = SqliteStore::open(&database_path)?;
    let mut backend = FailClosedBackend;
    let state = block_on_immediate(recover_session(&mut store, &mut backend))??;
    drop(store);

    let peer_policy = PeerPolicy::new(allowed_uid, cli_path);
    serve_forever(&socket_path, state, &peer_policy)?;
    Ok(())
}

fn create_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn block_on_immediate<F: Future>(future: F) -> Result<F::Output, Box<dyn Error>> {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = pin!(future);

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => Ok(output),
        Poll::Pending => Err("Focus P1 backend unexpectedly returned a pending future".into()),
    }
}
