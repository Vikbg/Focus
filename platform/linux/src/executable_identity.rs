use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io,
    os::{
        fd::{AsRawFd, BorrowedFd},
        unix::fs::{FileExt, MetadataExt, PermissionsExt},
    },
    path::Path,
};

use focus_core::{ExecutionOrigin, ObservedExecutable, PrivilegeTransition};
use rustix::{fs::fgetxattr, io::Errno};
use sha2::{Digest, Sha256};

const FILE_CAPABILITY_BUFFER_BYTES: usize = 64;
const FILE_CAPABILITY_XATTR: &str = "security.capability";
const HASH_BUFFER_BYTES: usize = 64 * 1024;
const SET_ID_MASK: u32 = 0o6000;

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
/// UTF-8, the target is not a regular file, the target has no execute permission bit, privilege
/// metadata cannot be inspected, or the file cannot be read completely for hashing.
pub fn observe_executable(
    path: impl AsRef<Path>,
    origin: ExecutionOrigin,
) -> Result<ObservedExecutable, ExecutableIdentityError> {
    let canonical = fs::canonicalize(path)?;
    let canonical_path = canonical
        .to_str()
        .ok_or(ExecutableIdentityError::NonUtf8Path)?
        .to_owned();

    let file = File::open(&canonical)?;
    observe_file(&file, canonical_path, origin)
}

/// Collects executable identity from an already-open kernel file descriptor.
///
/// The file descriptor is cloned and all metadata, privilege metadata, and digest reads stay bound
/// to that opened file description. The path is resolved through `/proc/self/fd` only to provide
/// path context; it is never reopened to choose which bytes are hashed.
///
/// # Errors
///
/// Returns an error if the descriptor cannot be cloned or resolved through procfs, the resolved
/// path is not UTF-8, the target is not a regular executable file, privilege metadata cannot be
/// inspected, or its bytes cannot be hashed.
pub fn observe_open_executable(
    fd: BorrowedFd<'_>,
    origin: ExecutionOrigin,
) -> Result<ObservedExecutable, ExecutableIdentityError> {
    let owned = fd.try_clone_to_owned()?;
    let file = File::from(owned);
    let proc_fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
    let canonical = fs::canonicalize(proc_fd_path)?;
    let canonical_path = canonical
        .to_str()
        .ok_or(ExecutableIdentityError::NonUtf8Path)?
        .to_owned();

    observe_file(&file, canonical_path, origin)
}

fn observe_file(
    file: &File,
    canonical_path: String,
    origin: ExecutionOrigin,
) -> Result<ObservedExecutable, ExecutableIdentityError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(ExecutableIdentityError::NotRegularFile);
    }
    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 {
        return Err(ExecutableIdentityError::NotExecutable);
    }
    let privilege_transition = classify_privilege_transition(mode, has_file_capabilities(file)?);

    let digest = hash_open_file(file)?;
    Ok(ObservedExecutable::new(canonical_path)
        .with_filesystem_identity(metadata.dev(), metadata.ino())
        .with_digest(digest)
        .with_origin(origin)
        .with_privilege_transition(privilege_transition))
}

const fn classify_privilege_transition(
    mode: u32,
    has_file_capabilities: bool,
) -> PrivilegeTransition {
    if has_file_capabilities {
        PrivilegeTransition::FileCapabilities
    } else if mode & SET_ID_MASK != 0 {
        PrivilegeTransition::SetId
    } else {
        PrivilegeTransition::None
    }
}

fn has_file_capabilities(file: &File) -> Result<bool, ExecutableIdentityError> {
    let mut value = [0_u8; FILE_CAPABILITY_BUFFER_BYTES];
    match fgetxattr(file, FILE_CAPABILITY_XATTR, &mut value[..]) {
        Ok(_) => Ok(true),
        Err(error) if error == Errno::NODATA || error == Errno::OPNOTSUPP => Ok(false),
        Err(error) => Err(io::Error::from_raw_os_error(error.raw_os_error()).into()),
    }
}

fn hash_open_file(file: &File) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES].into_boxed_slice();
    let mut offset = 0_u64;
    loop {
        let read = file.read_at(&mut buffer, offset)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("executable size overflow while hashing"))?;
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use focus_core::PrivilegeTransition;

    use super::classify_privilege_transition;

    #[test]
    fn file_capabilities_take_priority_over_setid_metadata() {
        assert_eq!(
            classify_privilege_transition(0o6755, true),
            PrivilegeTransition::FileCapabilities
        );
        assert_eq!(
            classify_privilege_transition(0o4755, false),
            PrivilegeTransition::SetId
        );
        assert_eq!(
            classify_privilege_transition(0o0755, false),
            PrivilegeTransition::None
        );
    }
}
