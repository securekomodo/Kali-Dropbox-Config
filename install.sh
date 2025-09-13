#!/usr/bin/env bash
set -euo pipefail

# ===================== helpers & CLI =====================
require_root(){ [[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }; }
log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
sanitize_hostname(){ echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/-+/-/g; s/^-+//; s/-+$//'; }
prompt(){ local v="$1" m="$2" d="${3:-}"; if [[ -n "${!v:-}" ]]; then return; fi; read -rp "$m${d:+ [$d]}: " x; [[ -z "$x" && -n "$d" ]] && x="$d"; declare -g "$v"="$x"; }
prompt_secret(){ local v="$1" m="$2"; if [[ -n "${!v:-}" ]]; then return; fi; read -rsp "$m: " x; echo; declare -g "$v"="$x"; }

need_reboot(){
  [[ -f /var/run/reboot-required ]] && return 0
  command -v needrestart >/dev/null 2>&1 && needrestart -b -r a 2>/dev/null | grep -qi "reboot is needed" && return 0
  return 1
}
maybe_prompt_reboot_and_exit(){
  if need_reboot; then
    echo
    echo "A reboot is required to continue."
    read -rp "Reboot now? (y/n) " yn
    if [[ "${yn,,}" == "y" ]]; then
      echo "After reboot, run this script again with the SAME command to continue."
      sleep 2
      reboot
    else
      echo "Please reboot later, then rerun this script to continue."
    fi
    exit 0
  fi
}

usage(){
  cat <<'USAGE'
Kali Dropbox Setup

Usage:
  sudo bash kali_dropbox_setup.sh help
  sudo bash kali_dropbox_setup.sh continue
  sudo bash kali_dropbox_setup.sh fresh-keep-conf
  sudo bash kali_dropbox_setup.sh fresh

Commands:
  help              Show this help (default if no arguments).
  continue          Resume using saved answers; skip completed steps.
  fresh-keep-conf   Clear progress markers; keep saved answers; then run.
  fresh             Clear progress and saved answers; rerun the wizard; then run.

Notes:
- No passwords are used for droplet bootstrap. You must add the pentester public key to droplet ROOT first.
- The script can remove that pentester key from ROOT after it migrates the key into the tunnel account.
USAGE
}

# ===================== state & config =====================
require_root
LOGFILE="/var/log/kali_dropbox_setup.log"
exec > >(tee -a "$LOGFILE") 2>&1

STATE_DIR="/var/lib/kali-dropbox-setup"
CONF_DIR="/etc/redline"
CONF_FILE="${CONF_DIR}/dropbox.conf"
mkdir -p "$STATE_DIR" "$CONF_DIR"; chmod 700 "$CONF_DIR"

mark(){ touch "${STATE_DIR}/$1.done"; }
donep(){ [[ -f "${STATE_DIR}/$1.done" ]]; }

save_conf(){
  cat >"$CONF_FILE" <<EOF
CLIENT_NAME='${CLIENT_NAME}'
HOSTNAME='${HOSTNAME}'
DROPLET_IP='${DROPLET_IP}'
DROPLET_SSH_PORT='${DROPLET_SSH_PORT}'
DROPLET_ROOT='${DROPLET_ROOT}'
TUNNEL_USER='${TUNNEL_USER}'
REVERSE_BIND_ADDR='${REVERSE_BIND_ADDR}'
REVERSE_REMOTE_PORT='${REVERSE_REMOTE_PORT}'
ENABLE_RDP='${ENABLE_RDP}'
EXPOSE_RDP_VIA_DROPLET='${EXPOSE_RDP_VIA_DROPLET}'
RDP_BIND_ADDR='${RDP_BIND_ADDR}'
RDP_REMOTE_PORT='${RDP_REMOTE_PORT}'
REMOVE_PENTESTER_KEY_FROM_ROOT='${REMOVE_PENTESTER_KEY_FROM_ROOT}'
DISABLE_PASSWORD_AUTH='${DISABLE_PASSWORD_AUTH}'
EOF
  chmod 600 "$CONF_FILE"
}
load_conf(){ [[ -f "$CONF_FILE" ]] && source "$CONF_FILE" || true; }

reset_state_only(){ rm -f "${STATE_DIR}/"*.done 2>/dev/null || true; echo "State cleared (kept ${CONF_FILE})."; }
reset_all(){ rm -f "${STATE_DIR}/"*.done 2>/dev/null || true; rm -f "$CONF_FILE" 2>/dev/null || true; echo "State and config cleared."; }

# ensure pentester key exists and handy SSH alias is created (for info)
ensure_local_ssh_identity() {
  local uhome="/home/pentester"
  local sshdir="$uhome/.ssh"
  local key="$sshdir/id_ed25519"
  local pub="${key}.pub"

  runuser -l pentester -c "mkdir -p '$sshdir'"
  chmod 700 "$sshdir"
  chown -R pentester:pentester "$sshdir"

  if ! runuser -l pentester -c "test -f '$key'"; then
    if runuser -l pentester -c "ssh-keygen -t ed25519 -N '' -f '$key' -C 'kali-dropbox'"; then :; else
      runuser -l pentester -c "ssh-keygen -t rsa -b 4096 -N '' -f '$uhome/.ssh/id_rsa' -C 'kali-dropbox'"
      key="$uhome/.ssh/id_rsa"
      pub="${key}.pub"
    fi
    echo "[INFO] Created SSH key: $key"
  fi

  chmod 600 "$key" "${pub}"
  chown pentester:pentester "$key" "${pub}"

  echo "[INFO] Public key (copy this to droplet ROOT):"
  cat "${pub}" || true
  echo "[INFO] Fingerprint:"
  ssh-keygen -lf "${pub}" -E sha256 || true

  # Save a short alias template for convenience (not required)
  local conf="$sshdir/config"
  touch "$conf"; chown pentester:pentester "$conf"; chmod 600 "$conf"
  awk 'BEGIN{skip=0} /^Host do-droplet$/{skip=1} skip&&/^[[:space:]]*$/ {skip=0; next} !skip {print}' "$conf" > "${conf}.tmp" 2>/dev/null || true
  mv -f "${conf}.tmp" "$conf" 2>/dev/null || true
  cat >> "$conf" <<EOF
Host do-droplet
  HostName ${DROPLET_IP:-<set after wizard>}
  Port ${DROPLET_SSH_PORT:-22}
  User ${DROPLET_ROOT:-root}
  StrictHostKeyChecking accept-new
EOF
  chown pentester:pentester "$conf"; chmod 600 "$conf"
}

# SSH wrappers using pentester key (no passwords)
get_pentester_pub(){
  [[ -f /home/pentester/.ssh/id_ed25519.pub ]] && echo "/home/pentester/.ssh/id_ed25519.pub" && return
  [[ -f /home/pentester/.ssh/id_rsa.pub ]] && echo "/home/pentester/.ssh/id_rsa.pub" && return
  return 1
}
get_pentester_key(){
  [[ -f /home/pentester/.ssh]()]()
