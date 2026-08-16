use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

use focus_linux::LinuxBackend;
use focus_storage::SqliteStore;
use focusd::{DaemonRuntime, DaemonService, PeerPolicy, RuntimeConfig};

const DEFAULT_DB_PATH: &str = "/var/lib/focus/focus.db";
const DEFAULT_SOCKET_PATH: &str = "/run/focus/focusd.sock";

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("focusd: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let database_path =
        PathBuf::from(env::var("FOCUS_DB_PATH").unwrap_or_else(|_| DEFAULT_DB_PATH.to_owned()));
    let socket_path = PathBuf::from(
        env::var("FOCUS_SOCKET_PATH").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_owned()),
    );
    let runtime_config = RuntimeConfig::from_env()?;

    create_parent(&database_path)?;
    let store = SqliteStore::open(&database_path)?;
    let backend = LinuxBackend::default();
    let mut service = DaemonService::new(store, backend);
    service.recover().await?;

    let runtime = DaemonRuntime::new(service);
    let peer_policy = PeerPolicy::new(
        runtime_config.allowed_uid(),
        runtime_config.cli_executable().to_path_buf(),
    );
    runtime
        .serve_until(&socket_path, &peer_policy, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn create_parent(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}
