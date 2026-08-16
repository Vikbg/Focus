#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TASK11_SCENARIOS = [
    "boot",
    "reboot",
    "suspend-resume",
    "daemon-restart",
    "multi-user",
]
TASK12_SCENARIOS = ["fanotify-permission"]

host = (ROOT / "tests/vm/run-qemu.sh").read_text(encoding="utf-8")
guest = (ROOT / "tests/vm/guest-runner.sh").read_text(encoding="utf-8")
testkit = (ROOT / "crates/focus-testkit/src/lib.rs").read_text(encoding="utf-8")

for scenario in TASK11_SCENARIOS + TASK12_SCENARIOS:
    if scenario not in host:
        raise SystemExit(f"host VM runner is missing scenario {scenario}")
    if scenario not in guest:
        raise SystemExit(f"guest VM runner is missing scenario {scenario}")
    if f'"{scenario}"' not in testkit:
        raise SystemExit(f"focus-testkit is missing fixture slug {scenario}")

required_host_markers = [
    "FOCUS_VM_BASE_IMAGE",
    "mktemp -d",
    "qemu-img create",
    "overlay.qcow2",
    "readonly=on",
    "cloud-localds",
    'qemu_pid=""',
    'kill "$qemu_pid"',
    'wait "$qemu_pid"',
]
for marker in required_host_markers:
    if marker not in host:
        raise SystemExit(f"disposable VM host runner is missing {marker}")

if "sudo " in host:
    raise SystemExit("host VM runner must never invoke sudo")

required_guest_markers = [
    "systemd-detect-virt --vm",
    "/sys/fs/cgroup/cgroup.controllers",
    "/proc/sys/fs/fanotify/max_queued_events",
    "nft --version",
    "systemctl reboot",
    "systemctl suspend",
    "FOCUS_ALLOWED_UID=0",
    "--test fanotify_live",
    "--ignored",
]
for marker in required_guest_markers:
    if marker not in guest:
        raise SystemExit(f"guest VM runner is missing {marker}")

print("Disposable Linux VM harness contract satisfied.")
