#!/usr/bin/env bash
set -euo pipefail

scenario="${1:-}"
case "$scenario" in
  boot|reboot|suspend-resume|daemon-restart|multi-user) ;;
  *)
    echo "usage: bash tests/vm/run-qemu.sh {boot|reboot|suspend-resume|daemon-restart|multi-user}" >&2
    exit 2
    ;;
esac

base_image="${FOCUS_VM_BASE_IMAGE:-}"
if [[ -z "$base_image" || ! -f "$base_image" ]]; then
  echo "FOCUS_VM_BASE_IMAGE must point to a prepared qcow2 cloud image" >&2
  exit 2
fi

for command_name in qemu-img qemu-system-x86_64 cloud-localds python3 timeout; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "missing host command: $command_name" >&2
    exit 2
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workdir="$(mktemp -d -t focus-vm.XXXXXX)"
trap 'rm -rf "$workdir"' EXIT INT TERM

overlay="$workdir/overlay.qcow2"
seed="$workdir/seed.img"
qmp="$workdir/qmp.sock"
log="$workdir/qemu.log"
base_image="$(realpath "$base_image")"

qemu-img create -q -f qcow2 -F qcow2 -b "$base_image" "$overlay"

cat >"$workdir/meta-data" <<EOF
instance-id: focus-${scenario}
local-hostname: focus-vm
EOF

cat >"$workdir/user-data" <<EOF
#cloud-config
write_files:
  - path: /etc/focus-vm-scenario
    owner: root:root
    permissions: '0644'
    content: |
      ${scenario}
  - path: /etc/systemd/system/focus-vm-harness.service
    owner: root:root
    permissions: '0644'
    content: |
      [Unit]
      Description=Focus disposable VM lifecycle harness
      After=local-fs.target
      RequiresMountsFor=/mnt/focus

      [Service]
      Type=oneshot
      Environment=FOCUS_VM_SCENARIO=${scenario}
      ExecStart=/bin/bash /mnt/focus/tests/vm/guest-runner.sh

      [Install]
      WantedBy=multi-user.target
runcmd:
  - mkdir -p /mnt/focus /var/lib/focus-vm-harness
  - grep -q '^focusrepo ' /etc/fstab || echo 'focusrepo /mnt/focus 9p trans=virtio,version=9p2000.L,ro,nofail 0 0' >> /etc/fstab
  - mount /mnt/focus
  - systemctl daemon-reload
  - systemctl enable focus-vm-harness.service
  - systemctl start focus-vm-harness.service
EOF

cloud-localds "$seed" "$workdir/user-data" "$workdir/meta-data"

qemu=(
  qemu-system-x86_64
  -machine q35
  -m 2048
  -smp 2
  -drive "file=$overlay,format=qcow2,if=virtio"
  -drive "file=$seed,format=raw,if=virtio,readonly=on"
  -virtfs "local,path=$repo_root,mount_tag=focusrepo,security_model=none,readonly=on"
  -nic user,model=virtio-net-pci
  -qmp "unix:$qmp,server=on,wait=off"
  -nographic
)

wake_suspended_guest() {
  python3 - "$qmp" <<'PY'
import json
import socket
import sys
import time

path = sys.argv[1]
deadline = time.monotonic() + 240
while not path or not __import__("os").path.exists(path):
    if time.monotonic() >= deadline:
        raise SystemExit("QMP socket did not appear")
    time.sleep(0.2)

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.connect(path)
    stream = client.makefile("rwb", buffering=0)
    stream.readline()
    stream.write(b'{"execute":"qmp_capabilities"}\n')
    stream.readline()

    while time.monotonic() < deadline:
        stream.write(b'{"execute":"query-status"}\n')
        reply = json.loads(stream.readline())
        status = reply.get("return", {}).get("status")
        if status == "suspended":
            stream.write(b'{"execute":"system_wakeup"}\n')
            stream.readline()
            raise SystemExit(0)
        time.sleep(1)

raise SystemExit("guest did not enter suspended state before timeout")
PY
}

if [[ "$scenario" == "suspend-resume" ]]; then
  timeout --signal=TERM 12m "${qemu[@]}" >"$log" 2>&1 &
  qemu_pid=$!
  wake_suspended_guest
  if ! wait "$qemu_pid"; then
    cat "$log" >&2
    exit 1
  fi
  cat "$log"
else
  timeout --signal=TERM 12m "${qemu[@]}" 2>&1 | tee "$log"
fi
