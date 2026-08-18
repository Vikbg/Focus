#!/usr/bin/env bash
set -euo pipefail

if ! systemd-detect-virt --vm >/dev/null 2>&1; then
  echo "refusing to run Focus systemd live fixture outside a virtual machine" >&2
  exit 90
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Focus systemd live fixture must run as root inside a disposable VM" >&2
  exit 90
fi

repo_root="${FOCUS_REPO_ROOT:-/mnt/focus}"
target_dir="${FOCUS_TARGET_DIR:-/var/tmp/focus-vm-target}"
allowed_uid="${FOCUS_ALLOWED_UID:-0}"
cli_path="${FOCUS_CLI_PATH:-/usr/bin/focusctl}"
keep_install="${FOCUS_KEEP_SYSTEMD_INSTALL:-0}"

focusd_install=/usr/libexec/focus/focusd
focusctl_install=/usr/bin/focusctl
service_install=/etc/systemd/system/focusd.service
env_install=/etc/focus/focusd.env
socket=/run/focus/focusd.sock
state_dir=/var/lib/focus
runtime_dir=/run/focus

for path in "$focusd_install" "$focusctl_install" "$service_install" "$env_install"; do
  if [[ -e "$path" || -L "$path" ]]; then
    echo "systemd live fixture refuses to replace existing path: $path" >&2
    exit 1
  fi
done

cleanup() {
  if [[ "$keep_install" == "1" ]]; then
    return
  fi
  systemctl stop focusd.service >/dev/null 2>&1 || true
  systemctl disable focusd.service >/dev/null 2>&1 || true
  rm -f "$service_install" "$env_install" "$focusd_install" "$focusctl_install"
  systemctl daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_socket() {
  for _ in $(seq 1 200); do
    if [[ -S "$socket" ]]; then
      return 0
    fi
    sleep 0.05
  done
  echo "daemon socket did not appear: $socket" >&2
  return 1
}

wait_for_restarted_service() {
  local old_pid="$1"
  for _ in $(seq 1 200); do
    new_pid="$(systemctl show --property MainPID --value focusd.service)"
    if [[ "$new_pid" =~ ^[0-9]+$ ]] \
      && (( new_pid > 1 )) \
      && [[ "$new_pid" != "$old_pid" ]] \
      && systemctl is-active --quiet focusd.service; then
      wait_for_socket
      return 0
    fi
    sleep 0.05
  done
  echo "focusd.service did not restart with a new MainPID" >&2
  return 1
}

prebuilt_focusd="$repo_root/.focus-vm-bin/focusd"
prebuilt_focusctl="$repo_root/.focus-vm-bin/focusctl"
if [[ -x "$prebuilt_focusd" && -x "$prebuilt_focusctl" ]]; then
  focusd_bin="$prebuilt_focusd"
  focusctl_bin="$prebuilt_focusctl"
else
  command -v cargo >/dev/null 2>&1
  mkdir -p "$target_dir"
  CARGO_TARGET_DIR="$target_dir" cargo build \
    --manifest-path "$repo_root/Cargo.toml" \
    --locked \
    -p focusd \
    -p focusctl
  focusd_bin="$target_dir/debug/focusd"
  focusctl_bin="$target_dir/debug/focusctl"
fi

service_source="$repo_root/platform/linux/systemd/focusd.service"
env_source="$target_dir/focusd.env"
mkdir -p "$target_dir"

printf '%s\n' \
  "FOCUS_ALLOWED_UID=$allowed_uid" \
  "FOCUS_CLI_PATH=$cli_path" \
  >"$env_source"

install -D -o root -g root -m 0755 "$focusd_bin" /usr/libexec/focus/focusd
install -D -o root -g root -m 0755 "$focusctl_bin" /usr/bin/focusctl
install -D -o root -g root -m 0644 "$service_source" /etc/systemd/system/focusd.service
install -D -o root -g root -m 0600 "$env_source" /etc/focus/focusd.env

[[ "$(stat -c '%u:%g %a' /etc/systemd/system/focusd.service)" == "0:0 644" ]]
[[ "$(stat -c '%u:%g %a' /etc/focus/focusd.env)" == "0:0 600" ]]
[[ "$(stat -c '%u:%g %a' /usr/libexec/focus/focusd)" == "0:0 755" ]]
[[ "$(stat -c '%u:%g %a' /usr/bin/focusctl)" == "0:0 755" ]]

systemctl daemon-reload
systemctl enable --now focusd.service
systemctl is-enabled --quiet focusd.service
systemctl is-active --quiet focusd.service
wait_for_socket

[[ "$(stat -c '%u:%g %a' /run/focus)" == "0:0 750" ]]
[[ "$(stat -c '%u:%g %a' /var/lib/focus)" == "0:0 700" ]]

FOCUS_SOCKET_PATH="$socket" "$focusctl_install" status \
  | grep -F "Focus daemon: running"

old_pid="$(systemctl show --property MainPID --value focusd.service)"
[[ "$old_pid" =~ ^[0-9]+$ ]]
(( old_pid > 1 ))
kill -KILL "$old_pid"
wait_for_restarted_service "$old_pid"

FOCUS_SOCKET_PATH="$socket" "$focusctl_install" status \
  | grep -F "Focus daemon: running"

new_pid="$(systemctl show --property MainPID --value focusd.service)"
[[ "$new_pid" =~ ^[0-9]+$ ]]
(( new_pid > 1 ))
[[ "$new_pid" != "$old_pid" ]]

[[ -d "$runtime_dir" ]]
[[ -d "$state_dir" ]]

if [[ "$keep_install" != "1" ]]; then
  systemctl stop focusd.service
  ! systemctl is-active --quiet focusd.service
  [[ ! -e "$socket" ]]
  systemctl disable focusd.service
fi
