#!/usr/bin/env bash
set -euo pipefail

if ! systemd-detect-virt --vm >/dev/null 2>&1; then
  echo "refusing to run Focus privileged VM fixtures outside a virtual machine" >&2
  exit 90
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Focus VM lifecycle fixtures must run as root inside the disposable guest" >&2
  exit 90
fi

scenario="${FOCUS_VM_SCENARIO:-$(cat /etc/focus-vm-scenario 2>/dev/null || true)}"
case "$scenario" in
  boot|reboot|suspend-resume|daemon-restart|multi-user|fanotify-permission|privilege-gate) ;;
  *)
    echo "unknown Focus VM scenario: $scenario" >&2
    exit 2
    ;;
esac

state_dir="/var/lib/focus-vm-harness"
mkdir -p "$state_dir"

log() {
  printf '%s\n' "$*" | tee -a "$state_dir/events.log"
}

require_common_preflight() {
  [[ -d /run/systemd/system ]]
  [[ -f /sys/fs/cgroup/cgroup.controllers ]]
  [[ -f /proc/sys/fs/fanotify/max_queued_events ]]
  command -v nft >/dev/null 2>&1
  nft --version >/dev/null

  [[ "$(stat -c '%u' /run)" == "0" ]]
  mode="$(stat -c '%a' /run)"
  world_digit="${mode: -1}"
  if (( (10#$world_digit & 2) != 0 )); then
    echo "/run is unexpectedly world-writable" >&2
    exit 1
  fi
}

finish_success() {
  log "scenario=$scenario result=success"
  printf '%s\n' "$scenario" >"$state_dir/result"
  sync
  systemctl poweroff
}

wait_for_focusd_service_after_reboot() {
  for _ in $(seq 1 200); do
    if systemctl is-enabled --quiet focusd.service \
      && systemctl is-active --quiet focusd.service \
      && [[ -S /run/focus/focusd.sock ]]; then
      return 0
    fi
    sleep 0.05
  done
  echo "focusd.service did not start automatically after reboot" >&2
  return 1
}

run_daemon_restart_fixture() {
  command -v cargo >/dev/null 2>&1
  FOCUS_REPO_ROOT=/mnt/focus \
  FOCUS_ALLOWED_UID=0 \
  FOCUS_CLI_PATH=/usr/bin/focusctl \
    bash /mnt/focus/tests/vm/systemd-service-live.sh
}

run_multi_user_fixture() {
  for user in focusvm1 focusvm2; do
    if ! id "$user" >/dev/null 2>&1; then
      useradd --create-home "$user"
    fi
    uid="$(id -u "$user")"
    systemctl start "user@${uid}.service"
  done

  active_users=0
  if [[ -d /run/systemd/users ]]; then
    for entry in /run/systemd/users/*; do
      [[ -e "$entry" ]] || continue
      name="${entry##*/}"
      if [[ "$name" =~ ^[0-9]+$ ]] && [[ "$name" != "0" ]]; then
        active_users=$((active_users + 1))
      fi
    done
  fi
  if (( active_users < 2 )); then
    echo "multi-user fixture did not create two active non-root user managers" >&2
    exit 1
  fi
}

run_fanotify_permission_fixture() {
  command -v cargo >/dev/null 2>&1
  target_dir="/var/tmp/focus-vm-target"
  mkdir -p "$target_dir"

  FOCUS_VM_SCENARIO=fanotify-permission \
  CARGO_TARGET_DIR="$target_dir" \
    cargo test \
      --manifest-path /mnt/focus/Cargo.toml \
      --locked \
      -p focus-linux \
      --test fanotify_live \
      -- \
      --ignored \
      --nocapture
}

run_privilege_gate_fixture() {
  command -v cargo >/dev/null 2>&1
  target_dir="/var/tmp/focus-vm-target"
  mkdir -p "$target_dir"

  FOCUS_VM_SCENARIO=privilege-gate \
  CARGO_TARGET_DIR="$target_dir" \
    cargo test \
      --manifest-path /mnt/focus/Cargo.toml \
      --locked \
      -p focus-linux \
      --test privilege_gate_live \
      -- \
      --ignored \
      --nocapture
}

require_common_preflight
boot_id="$(cat /proc/sys/kernel/random/boot_id)"
log "scenario=$scenario boot_id=$boot_id"

case "$scenario" in
  boot)
    finish_success
    ;;
  reboot)
    marker="$state_dir/reboot-boot-id"
    if [[ ! -f "$marker" ]]; then
      FOCUS_REPO_ROOT=/mnt/focus \
      FOCUS_ALLOWED_UID=0 \
      FOCUS_CLI_PATH=/usr/bin/focusctl \
      FOCUS_KEEP_SYSTEMD_INSTALL=1 \
        bash /mnt/focus/tests/vm/systemd-service-live.sh
      systemctl is-enabled --quiet focusd.service
      printf '%s\n' "$boot_id" >"$marker"
      sync
      systemctl reboot
      exit 0
    fi
    old_boot_id="$(cat "$marker")"
    if [[ "$old_boot_id" == "$boot_id" ]]; then
      echo "reboot fixture retained the same boot id" >&2
      exit 1
    fi
    wait_for_focusd_service_after_reboot
    systemctl is-enabled --quiet focusd.service
    systemctl is-active --quiet focusd.service
    FOCUS_SOCKET_PATH=/run/focus/focusd.sock /usr/bin/focusctl status \
      | grep -F "Focus daemon: running"
    finish_success
    ;;
  suspend-resume)
    before_boot_id="$boot_id"
    log "suspending guest"
    systemctl suspend
    after_boot_id="$(cat /proc/sys/kernel/random/boot_id)"
    if [[ "$before_boot_id" != "$after_boot_id" ]]; then
      echo "suspend/resume unexpectedly changed Linux boot id" >&2
      exit 1
    fi
    log "guest resumed"
    finish_success
    ;;
  daemon-restart)
    run_daemon_restart_fixture
    finish_success
    ;;
  multi-user)
    run_multi_user_fixture
    finish_success
    ;;
  fanotify-permission)
    run_fanotify_permission_fixture
    finish_success
    ;;
  privilege-gate)
    run_privilege_gate_fixture
    finish_success
    ;;
esac
