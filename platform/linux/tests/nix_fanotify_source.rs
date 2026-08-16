use focus_linux::{FanotifyPermissionSource, NixFanotifyPermissionSource};
use nix::sys::fanotify::{EventFFlags, InitFlags, MarkFlags, MaskFlags};

fn assert_permission_source<T: FanotifyPermissionSource>() {}

#[test]
fn nix_source_implements_permission_transport_contract() {
    assert_permission_source::<NixFanotifyPermissionSource>();
}

#[test]
fn nix_source_uses_fail_closed_permission_configuration() {
    let init = NixFanotifyPermissionSource::init_flags();
    assert!(init.contains(InitFlags::FAN_CLASS_CONTENT));
    assert!(init.contains(InitFlags::FAN_CLOEXEC));
    assert!(init.contains(InitFlags::FAN_NONBLOCK));
    assert!(!init.contains(InitFlags::FAN_CLASS_NOTIF));
    assert!(!init.contains(InitFlags::FAN_CLASS_PRE_CONTENT));

    let event = NixFanotifyPermissionSource::event_flags();
    assert!(event.contains(EventFFlags::O_RDONLY));
    assert!(event.contains(EventFFlags::O_CLOEXEC));
    assert!(event.contains(EventFFlags::O_LARGEFILE));

    let mark = NixFanotifyPermissionSource::mount_mark_flags();
    assert!(mark.contains(MarkFlags::FAN_MARK_ADD));
    assert!(mark.contains(MarkFlags::FAN_MARK_MOUNT));

    assert_eq!(
        NixFanotifyPermissionSource::event_mask(),
        MaskFlags::FAN_OPEN_EXEC_PERM
    );
}
