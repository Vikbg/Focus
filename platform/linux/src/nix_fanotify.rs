use std::{
    collections::VecDeque,
    fs::File,
    io,
    os::fd::{AsFd, BorrowedFd},
    path::Path,
};

use nix::{
    errno::Errno,
    sys::fanotify::{
        EventFFlags, Fanotify, FanotifyEvent, FanotifyResponse, InitFlags, MarkFlags, MaskFlags,
        Response,
    },
};

use crate::{ExecutionPermission, FanotifyExecutionEvent, FanotifyPermissionSource};

/// Nix-backed fanotify permission source used by the Linux process guard.
#[derive(Debug)]
pub struct NixFanotifyPermissionSource {
    fanotify: Fanotify,
    queued: VecDeque<FanotifyEvent>,
    pending: Option<FanotifyEvent>,
}

impl NixFanotifyPermissionSource {
    /// Fanotify initialization flags required by the Focus pre-exec guard.
    #[must_use]
    pub fn init_flags() -> InitFlags {
        InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_CLOEXEC | InitFlags::FAN_NONBLOCK
    }

    /// File status flags used for kernel-opened event descriptors.
    #[must_use]
    pub fn event_flags() -> EventFFlags {
        EventFFlags::O_RDONLY | EventFFlags::O_CLOEXEC | EventFFlags::O_LARGEFILE
    }

    /// Mark flags used to cover one mounted filesystem.
    #[must_use]
    pub fn mount_mark_flags() -> MarkFlags {
        MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT
    }

    /// Permission event mask enforced by the process guard.
    #[must_use]
    pub fn event_mask() -> MaskFlags {
        MaskFlags::FAN_OPEN_EXEC_PERM
    }

    /// Creates a fanotify group and marks every supplied absolute mount path.
    ///
    /// # Errors
    ///
    /// Returns an error when fanotify initialization fails, a mount path is relative, the root
    /// directory cannot be opened for the mark call, or any mount cannot be marked.
    pub fn new_for_mounts<I, P>(mounts: I) -> io::Result<Self>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let fanotify =
            Fanotify::init(Self::init_flags(), Self::event_flags()).map_err(errno_to_io)?;
        let root = File::open("/")?;

        for mount in mounts {
            let mount = mount.as_ref();
            if !mount.is_absolute() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "fanotify mount path must be absolute",
                ));
            }
            fanotify
                .mark(
                    Self::mount_mark_flags(),
                    Self::event_mask(),
                    &root,
                    Some(mount),
                )
                .map_err(errno_to_io)?;
        }

        Ok(Self {
            fanotify,
            queued: VecDeque::new(),
            pending: None,
        })
    }

    fn refill(&mut self) -> io::Result<()> {
        match self.fanotify.read_events() {
            Ok(events) => {
                self.queued.extend(events);
                Ok(())
            }
            Err(Errno::EAGAIN) => Ok(()),
            Err(error) => Err(errno_to_io(error)),
        }
    }
}

impl AsFd for NixFanotifyPermissionSource {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fanotify.as_fd()
    }
}

impl FanotifyPermissionSource for NixFanotifyPermissionSource {
    fn next_event(&mut self) -> io::Result<Option<FanotifyExecutionEvent>> {
        if self.pending.is_some() {
            return Err(io::Error::other(
                "fanotify permission event is still awaiting a response",
            ));
        }
        if self.queued.is_empty() {
            self.refill()?;
        }

        let Some(event) = self.queued.pop_front() else {
            return Ok(None);
        };
        if !event.check_version() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fanotify event metadata version mismatch",
            ));
        }
        if event.mask().contains(MaskFlags::FAN_Q_OVERFLOW) || event.fd().is_none() {
            return Err(io::Error::other("fanotify event queue overflowed"));
        }
        if event.mask() != MaskFlags::FAN_OPEN_EXEC_PERM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected fanotify event mask",
            ));
        }

        let requester_pid = event.pid();
        if requester_pid <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fanotify event has invalid requester pid",
            ));
        }
        let requester_pid = u32::try_from(requester_pid).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "fanotify requester pid does not fit u32",
            )
        })?;
        let target = event
            .fd()
            .ok_or_else(|| io::Error::other("fanotify event missing target fd"))?
            .try_clone_to_owned()?;
        let target = File::from(target);

        self.pending = Some(event);
        Ok(Some(FanotifyExecutionEvent::new(target, requester_pid)))
    }

    fn respond(&mut self, permission: ExecutionPermission) -> io::Result<()> {
        let event = self.pending.as_ref().ok_or_else(|| {
            io::Error::other("fanotify response requested without a pending event")
        })?;
        let fd = event
            .fd()
            .ok_or_else(|| io::Error::other("pending fanotify event lost target fd"))?;
        let response = match permission {
            ExecutionPermission::Allow => Response::FAN_ALLOW,
            ExecutionPermission::Deny => Response::FAN_DENY,
        };

        self.fanotify
            .write_response(FanotifyResponse::new(fd, response))
            .map_err(errno_to_io)?;
        self.pending.take();
        Ok(())
    }
}

fn errno_to_io(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}
