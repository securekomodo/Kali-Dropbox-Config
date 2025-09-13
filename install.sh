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
      echo "After reboot, run this script again with the same command to continue."
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
- If a reboot is required, the script will ask first, then exit. After reboot, run the same command again to continue.
- The one-time droplet root password is NOT saved to disk.
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
EOF
  chmod 600 "$CONF_FILE"
}
load_conf(){ [[ -f "$CONF_FILE" ]] && source "$CONF_FILE" || true; }

reset_state_only(){ rm -f "${STATE_DIR}/"*.done 2>/dev/null || true; echo "State cleared (kept ${CONF_FILE})."; }
reset_all(){ rm -f "${STATE_DIR}/"*.done 2>/dev/null || true; rm -f "$CONF_FILE" 2>/dev/null || true; echo "State and config cleared."; }

ensure_local_ssh_identity() {
  local uhome="/home/pentester"
  local sshdir="$uhome/.ssh"
  local key="$sshdir/id_ed25519"
  local pub="${key}.pub"

  runuser -l pentester -c "mkdir -p '$sshdir'"
  chmod 700 "$sshdir"
  chown -R pentester:pentester "$sshdir"

  if ! runuser -l pentester -c "test -f '$key'"; then
    if runuser -l pentester -c "ssh-keygen -t ed25519 -N '' -f '$key' -C 'kali-dropbox'"; then
      :
    else
      runuser -l pentester -c "ssh-keygen -t rsa -b 4096 -N '' -f '$uhome/.ssh/id_rsa' -C 'kali-dropbox'"
      key="$uhome/.ssh/id_rsa"
      pub="${key}.pub"
    fi
    echo "[INFO] Created SSH key: $key"
  fi

  chmod 600 "$key" "${pub}"
  chown pentester:pentester "$key" "${pub}"

  echo "[INFO] Public key:"
  cat "${pub}" || true
  echo "[INFO] Fingerprint:"
  ssh-keygen -lf "${pub}" -E sha256 || true

  # SSH alias for droplet
  local conf="$sshdir/config"
  touch "$conf"
  chown pentester:pentester "$conf"
  chmod 600 "$conf"

  # remove any prior do-droplet block, then write fresh
  awk 'BEGIN{skip=0} /^Host do-droplet$/{skip=1} skip&&/^[[:space:]]*$/ {skip=0; next} !skip {print}' "$conf" > "${conf}.tmp" 2>/dev/null || true
  mv -f "${conf}.tmp" "$conf" 2>/dev/null || true

  cat >> "$conf" <<EOF
Host do-droplet
  HostName ${DROPLET_IP}
  Port ${DROPLET_SSH_PORT}
  User ${TUNNEL_USER}
  ServerAliveInterval 30
  ServerAliveCountMax 3
  StrictHostKeyChecking accept-new
  UserKnownHostsFile ~/.ssh/known_hosts
EOF
  chown pentester:pentester "$conf"
  chmod 600 "$conf"
}

# ===================== CLI parse =====================
cmd="${1:-help}"
case "$cmd" in
  help|-h|--help) usage; exit 0 ;;
  continue|--continue) : ;;
  fresh-keep-conf|--fresh-keep-conf) reset_state_only ;;
  fresh|--fresh)
    echo "This will wipe progress and saved answers, starting from scratch."
    read -rp "Type YES to confirm: " c; [[ "$c" == "YES" ]] || { echo "Aborted."; exit 1; }
    reset_all
    ;;
  *)
    usage; exit 1 ;;
esac

echo; log "Kali Dropbox Setup: $cmd"
load_conf

# ===================== prereq wizard (runs once) =====================
if ! donep prereq; then
  prompt CLIENT_NAME "Client company name (e.g., Acme123)"
  suggest="$(sanitize_hostname "$CLIENT_NAME")"; [[ -z "$suggest" ]] && suggest="client"
  suggest="${suggest}-linux-vm"
  echo "Suggested hostname: $suggest"
  prompt HOSTNAME "Confirm or enter alternate hostname" "$suggest"
  HOSTNAME="$(sanitize_hostname "$HOSTNAME")"; [[ -z "$HOSTNAME" ]] && { echo "Hostname cannot be empty"; exit 1; }

  echo
  echo "DigitalOcean droplet bootstrap (one time; switches to key-only after setup)"
  prompt DROPLET_IP "Droplet public IP or DNS"
  prompt DROPLET_SSH_PORT "Droplet SSH port" "22"
  prompt DROPLET_ROOT "Droplet root username" "root"
  # Do NOT save the password; we prompt when needed
  prompt TUNNEL_USER "Dedicated tunnel username to create on droplet" "tunnel"

  echo
  echo "Reverse SSH settings"
  prompt REVERSE_REMOTE_PORT "Remote port for SSH on droplet" "20022"
  prompt REVERSE_BIND_ADDR "Bind address on droplet for SSH reverse (localhost or 0.0.0.0)" "localhost"

  echo
  read -rp "Enable RDP on this box? (y/n) " yn; [[ "${yn,,}" == "y" ]] && ENABLE_RDP="yes" || ENABLE_RDP="no"
  EXPOSE_RDP_VIA_DROPLET="no"; RDP_REMOTE_PORT=""; RDP_BIND_ADDR="localhost"
  if [[ "$ENABLE_RDP" == "yes" ]]; then
    read -rp "Also expose RDP via droplet? (y/n) " yn2
    if [[ "${yn2,,}" == "y" ]]; then
      EXPOSE_RDP_VIA_DROPLET="yes"
      prompt RDP_REMOTE_PORT "Remote port for RDP on droplet" "23389"
      prompt RDP_BIND_ADDR "Bind address on droplet for RDP reverse (localhost or 0.0.0.0)" "localhost"
    fi
  fi

  echo
  echo "----- Review -----"
  echo "Client:            $CLIENT_NAME"
  echo "Hostname:          $HOSTNAME"
  echo "Droplet root:      $DROPLET_ROOT@$DROPLET_IP:$DROPLET_SSH_PORT"
  echo "Tunnel user:       $TUNNEL_USER"
  echo "SSH reverse:       ${REVERSE_BIND_ADDR}:${REVERSE_REMOTE_PORT} -> localhost:22"
  if [[ "$ENABLE_RDP" == "yes" ]]; then
    echo "RDP local:         enabled on 3389"
    [[ "$EXPOSE_RDP_VIA_DROPLET" == "yes" ]] && echo "RDP reverse:       ${RDP_BIND_ADDR}:${RDP_REMOTE_PORT} -> localhost:3389"
  fi
  echo "------------------"
  read -rp "Proceed with these settings? (y/n) " ok; [[ "${ok,,}" == "y" ]] || { echo "Aborted."; exit 1; }
  save_conf
  mark prereq
fi
load_conf

# ===================== steps =====================
# 1 hostname and time
if ! donep step1; then
  log "Configuring hostname"
  hostnamectl set-hostname "$HOSTNAME"
  grep -q "$HOSTNAME" /etc/hosts || echo "127.0.1.1 $HOSTNAME" >> /etc/hosts
  timedatectl set-ntp true || true
  mark step1
fi

# 2 ensure pentester user
if ! donep step2; then
  log "Ensuring user 'pentester'"
  if ! id pentester &>/dev/null; then
    useradd -m -s /bin/bash pentester
    echo "Set password for pentester (console and optional RDP)"
    passwd pentester
    usermod -aG sudo pentester
  fi
  echo "pentester ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/010_pentester_nopasswd
  chmod 440 /etc/sudoers.d/010_pentester_nopasswd
  mark step2
fi

# 3 base update
if ! donep step3; then
  log "Updating system"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get -o Dpkg::Options::="--force-confnew" dist-upgrade -y
  apt-get autoremove -y; apt-get autoclean -y
  apt-get install -y needrestart || true
  mark step3
  maybe_prompt_reboot_and_exit
fi

# 4 core tooling (NO BloodHound)
if ! donep step4; then
  log "Installing core tools"
  apt-get update -y
  apt-get install -y \
    git tmux vim jq curl wget unzip ca-certificates \
    build-essential python3 python3-pip python3-venv golang \
    nmap masscan amass crackmapexec \
    feroxbuster gobuster ffuf \
    impacket-scripts responder \
    net-tools dnsutils socat autossh sshpass ufw \
    nuclei zaproxy chromium openssh-server htop seclists
  runuser -l pentester -c 'nuclei -update-templates || true'
  systemctl enable ssh; systemctl restart ssh

  if [[ "$ENABLE_RDP" == "yes" ]]; then
    log "Enabling RDP"
    apt-get install -y xrdp xorgxrdp
    id -u xrdp >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin xrdp || true
    adduser xrdp ssl-cert || true
    echo "startxfce4" > /home/pentester/.xsession
    chown pentester:pentester /home/pentester/.xsession
    systemctl enable xrdp
    systemctl restart xrdp
  fi

  mark step4
  maybe_prompt_reboot_and_exit
fi

# 5 sshd hardening
if ! donep step5; then
  log "Hardening local sshd"
  sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  sed -i 's/^#\?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
  sed -i 's/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
  grep -q '^ClientAliveInterval' /etc/ssh/sshd_config || echo 'ClientAliveInterval 60' >> /etc/ssh/sshd_config
  grep -q '^ClientAliveCountMax' /etc/ssh/sshd_config || echo 'ClientAliveCountMax 3' >> /etc/ssh/sshd_config
  systemctl restart ssh
  for t in sleep.target suspend.target hibernate.target hybrid-sleep.target; do systemctl mask "$t" || true; done
  mark step5
fi

# 6 ensure local key and alias
if ! donep step6; then
  log "Ensuring SSH key and alias for pentester"
  ensure_local_ssh_identity
  mark step6
fi

# 7 droplet bootstrap (try key first; else one-time root password; then key-only)
if ! donep step7; then
  log "Checking droplet key access"
  if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -p "$DROPLET_SSH_PORT" "$TUNNEL_USER@$DROPLET_IP" true 2>/dev/null; then
    log "Key access as $TUNNEL_USER already works; skipping bootstrap"
  else
    # prompt now (not saved to disk)
    prompt_secret DROPLET_PW "Droplet root password (used once; not saved)"
    export SSHPASS="$DROPLET_PW"

    # convenience wrappers
    remote_root_exec(){
      sshpass -e ssh \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no \
        -p "$DROPLET_SSH_PORT" "$DROPLET_ROOT@$DROPLET_IP" "$@"
    }
    remote_root_scp(){
      sshpass -e scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -P "$DROPLET_SSH_PORT" "$1" "$DROPLET_ROOT@$DROPLET_IP:$2"
    }

    log "[Droplet] creating $TUNNEL_USER and installing key"
    remote_root_exec "id -u $TUNNEL_USER >/dev/null 2>&1 || useradd -m -s /bin/bash $TUNNEL_USER"
    remote_root_exec "mkdir -p /home/$TUNNEL_USER/.ssh && chmod 700 /home/$TUNNEL_USER/.ssh"

    PUB="/home/pentester/.ssh/id_ed25519.pub"; [[ -f "$PUB" ]] || PUB="/home/pentester/.ssh/id_rsa.pub"
    [[ -f "$PUB" ]] || { echo "Missing public key for pentester"; exit 1; }
    remote_root_scp "$PUB" "/tmp/pentester_key.pub"

    remote_root_exec "auth='/home/$TUNNEL_USER/.ssh/authorized_keys'; touch \"\$auth\"; \
      grep -qxF \"\$(cat /tmp/pentester_key.pub)\" \"\$auth\" || cat /tmp/pentester_key.pub >> \"\$auth\"; \
      rm -f /tmp/pentester_key.pub; \
      chown -R $TUNNEL_USER:$TUNNEL_USER /home/$TUNNEL_USER/.ssh; chmod 600 \"\$auth\""

    log "[Droplet] hardening sshd to key-only and disabling root login"
    remote_root_exec "cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null || true"
    remote_root_exec "sed -i 's/^#\\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config"
    remote_root_exec "sed -i 's/^#\\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config"
    remote_root_exec "sed -i 's/^#\\?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config"
    remote_root_exec "sed -i 's/^#\\?AllowTcpForwarding .*/AllowTcpForwarding yes/' /etc/ssh/sshd_config"

    if [[ "$REVERSE_BIND_ADDR" == "0.0.0.0" || "${RDP_BIND_ADDR:-}" == "0.0.0.0" ]]; then
      remote_root_exec "grep -q '^GatewayPorts ' /etc/ssh/sshd_config && \
        sed -i 's/^GatewayPorts .*/GatewayPorts clientspecified/' /etc/ssh/sshd_config || \
        echo 'GatewayPorts clientspecified' >> /etc/ssh/sshd_config"
    fi

    remote_root_exec "systemctl restart ssh"
    log "[Droplet] sshd restarted; root password login closed"
  fi
  mark step7
fi

# 8 autossh reverse service
if ! donep step8; then
  log "Creating autossh reverse-tunnel service"
  cat >/etc/autossh-reverse-tunnel.conf <<EOF
AUTOSSH_GATETIME=0
AUTOSSH_PORT=0
DROPLET_IP="${DROPLET_IP}"
DROPLET_SSH_PORT="${DROPLET_SSH_PORT}"
TUNNEL_USER="${TUNNEL_USER}"
REVERSE_BIND_ADDR="${REVERSE_BIND_ADDR}"
REVERSE_REMOTE_PORT="${REVERSE_REMOTE_PORT}"
EXPOSE_RDP_VIA_DROPLET="${EXPOSE_RDP_VIA_DROPLET}"
RDP_BIND_ADDR="${RDP_BIND_ADDR}"
RDP_REMOTE_PORT="${RDP_REMOTE_PORT}"
LOCAL_SSH_PORT="22"
LOCAL_RDP_PORT="3389"
PENTESTER_HOME="/home/pentester"
EOF
  chmod 600 /etc/autossh-reverse-tunnel.conf

  cat >/usr/local/bin/start-reverse-tunnel.sh <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
source /etc/autossh-reverse-tunnel.conf
CMD=(/usr/bin/autossh -M 0 -N
     -o "ServerAliveInterval=30" -o "ServerAliveCountMax=3" -o "ExitOnForwardFailure=yes"
     -i "${PENTESTER_HOME}/.ssh/id_ed25519"
     -R "${REVERSE_BIND_ADDR}:${REVERSE_REMOTE_PORT}:localhost:${LOCAL_SSH_PORT}")
if [[ "${EXPOSE_RDP_VIA_DROPLET}" == "yes" && -n "${RDP_REMOTE_PORT}" ]]; then
  CMD+=(-R "${RDP_BIND_ADDR}:${RDP_REMOTE_PORT}:localhost:${LOCAL_RDP_PORT}")
fi
CMD+=(-p "${DROPLET_SSH_PORT}" "${TUNNEL_USER}@${DROPLET_IP}")
exec "${CMD[@]}"
EOS
  chmod +x /usr/local/bin/start-reverse-tunnel.sh

  cat >/etc/systemd/system/autossh-reverse-tunnel.service <<'EOF'
[Unit]
Description=Persistent reverse SSH tunnel to droplet (SSH and optional RDP)
After=network.target ssh.service
Wants=network.target
[Service]
Type=simple
EnvironmentFile=/etc/autossh-reverse-tunnel.conf
User=pentester
Group=pentester
ExecStart=/usr/local/bin/start-reverse-tunnel.sh
Restart=always
RestartSec=5s
NoNewPrivileges=yes
PrivateTmp=yes
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now autossh-reverse-tunnel.service
  mark step8
fi

# 9 validate helper
if ! donep step9; then
  log "Installing validation helper"
  cat >/usr/local/bin/validate_kali.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
err=0; chk(){ printf "%-44s" "$1"; shift; if "$@"; then echo ok; else echo fail; err=1; fi; }
chk "Hostname set" bash -c '[[ -n "$(hostname)" ]]'
chk "User pentester exists" id pentester
chk "SSHD active" systemctl is-active --quiet ssh
chk "autossh active" systemctl is-active --quiet autossh-reverse-tunnel.service
chk "nmap present" command -v nmap >/dev/null
chk "nuclei present" command -v nuclei >/dev/null
if systemctl list-unit-files | grep -q '^xrdp.service'; then
  chk "xrdp enabled" systemctl is-enabled --quiet xrdp
  chk "xrdp active" systemctl is-active --quiet xrdp
fi
echo "Done. Errors: $err"; exit $err
EOF
  chmod +x /usr/local/bin/validate_kali.sh
  mark step9
fi

log "All steps complete"
echo
echo "Reverse SSH on droplet: ${REVERSE_BIND_ADDR}:${REVERSE_REMOTE_PORT} -> this host 22"
if [[ "${ENABLE_RDP}" == "yes" ]]; then
  echo "RDP enabled locally on 3389 for user 'pentester'."
  [[ "${EXPOSE_RDP_VIA_DROPLET}" == "yes" ]] && echo "RDP reverse on droplet: ${RDP_BIND_ADDR}:${RDP_REMOTE_PORT} -> this host 3389"
fi
echo "From the droplet shell: ssh -p ${REVERSE_REMOTE_PORT} pentester@127.0.0.1"
echo "Validate any time: /usr/local/bin/validate_kali.sh"
