# Disposable Linux enforcement VM

This harness exists so privileged Linux enforcement work is never developed or tested directly on a daily-use host.

## Host requirements

Use a prepared x86_64 qcow2 cloud image with:

- cloud-init
- systemd
- cgroup v2
- fanotify support
- nftables
- virtio-9p guest filesystem support
- Rust stable and Cargo for the daemon-restart and fanotify fixtures

The host needs `qemu-system-x86_64`, `qemu-img`, `cloud-localds`, Python 3, and `timeout`.

Set the base image explicitly:

```bash
export FOCUS_VM_BASE_IMAGE=/path/to/focus-base.qcow2
```

Run one lifecycle or enforcement fixture at a time:

```bash
bash tests/vm/run-qemu.sh boot
bash tests/vm/run-qemu.sh reboot
bash tests/vm/run-qemu.sh suspend-resume
bash tests/vm/run-qemu.sh daemon-restart
bash tests/vm/run-qemu.sh multi-user
bash tests/vm/run-qemu.sh fanotify-permission
```

## Safety properties

`run-qemu.sh` never installs or arms Focus enforcement on the host. It creates a temporary qcow2 overlay, exports the repository to the guest through a read-only virtio-9p share, and deletes the overlay when QEMU exits.

`guest-runner.sh` refuses to perform any privileged fixture unless `systemd-detect-virt --vm` confirms that it is running in a virtual machine. Root-only operations such as reboot, suspend, user creation, nftables probing, daemon restart, and fanotify permission control happen only inside that disposable guest.

The suspend/resume scenario uses QMP from the host only to wake a guest after QEMU reports the guest as suspended.

## Scenario intent

- `boot`: verify the strict Linux prerequisites are present in a fresh guest boot.
- `reboot`: verify a real reboot changes the Linux boot ID and the enabled harness continues on the next boot.
- `suspend-resume`: suspend the guest, wake it through QMP, and verify the boot ID did not change.
- `daemon-restart`: build `focusd` and `focusctl` into guest-temporary storage, force one abrupt daemon stop, verify stale-socket recovery, then verify graceful shutdown cleanup.
- `multi-user`: start two non-root systemd user managers so the preflight multi-user condition can be exercised safely.
- `fanotify-permission`: run every ignored `fanotify_live` fixture, prove real pre-execution deny and allow behavior, exercise the production process guard with an isolated UID and mount, and print decision-latency and idle-watchdog metrics.

CI does not boot nested QEMU. It validates shell syntax and the harness safety contract. Real privileged enforcement tests are expected to run through this VM entry point.
