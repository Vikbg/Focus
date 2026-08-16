use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, Read},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use focus_core::{ExecutionOrigin, ObservedExecutable};
use sha2::{Digest, Sha256};

const HASH_BUFFER_BYTES: usize = 64 * 1024;

/// Error returned while collecting a Linux executable identity.
#[derive(Debug)]
pub enum ExecutableIdentityError {
    Io(io::Error),
    NonUtf8Path,
    NotRegularFile,
    NotExecutable,
}

impl fmt::Display for ExecutableIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "executable identity I/O error: {error}"),
            Self::NonUtf8Path => formatter.write_str("canonical executable path is not UTF-8"),
            Self::NotRegularFile => {
                formatter.write_str("executable identity target is not a regular file")
            }
            Self::NotExecutable => {
                formatter.write_str("executable identity target has no execute bit")
            }
        }
    }
}

impl Error for ExecutableIdentityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::NonUtf8Path | Self::NotRegularFile | Self::NotExecutable => None,
        }
    }
}

impl From<io::Error> for ExecutableIdentityError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Collects the canonical path, filesystem identity, and SHA-256 digest for one executable.
///
/// The metadata and digest are read from the same opened file handle. Symlink paths are
/// canonicalized before the handle is opened so policy decisions are based on the target file.
///
/// # Errors
///
/// Returns an error if the path cannot be canonicalized or opened, the canonical path is not
/// UTF-8, the target is not a regular file, the target has no execute permission bit, or the file
/// cannot be read completely for hashing.
pub fn observe_executable(
    path: impl AsRef<Path>,
    origin: ExecutionOrigin,
) -> Result<ObservedExecutable, ExecutableIdentityError> {
    let canonical = fs::canonicalize(path)?;
    let canonical_path = canonical
        .to_str()
        .ok_or(ExecutableIdentityError::NonUtf8Path)?
        .to_owned();

    let mut file = File::open(&canonical)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(ExecutableIdentityError::NotRegularFile);
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(ExecutableIdentityError::NotExecutable);
    }

    let digest = hash_open_file(&mut file)?;
    Ok(ObservedExecutable::new(canonical_path)
        .with_filesystem_identity(metadata.dev(), metadata.ino())
        .with_digest(digest)
        .with_origin(origin))
}

fn hash_open_file(file: &mut File) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}
