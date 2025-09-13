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
- Password-free bootstrap. You will add the pentester public key to droplet ROOT once, then the script verifies and continues.
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

# ensure pentester key exists and show it (never overwrites existing keys)
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

  # Optional alias template (updated after wizard vars exist)
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

# SSH wrappers using pentester key
get_pentester_pub(){
  [[ -f /home/pentester/.ssh/id_ed25519.pub ]] && echo "/home/pentester/.ssh/id_ed25519.pub" && return
  [[ -f /home/pentester/.ssh/id_rsa.pub   ]] && echo "/home/pentester/.ssh/id_rsa.pub" && return
  return 1
}
get_pentester_key(){
  [[ -f /home/pentester/.ssh/id_ed25519 ]] && echo "/home/pentester/.ssh/id_ed25519" && return
  [[ -f /home/pentester/.ssh/id_rsa     ]] && echo "/home/pentester/.ssh/id_rsa" && return
  return 1
}
remote_root_key_ssh(){ # args: <cmd...>
  local keyfile; keyfile="$(get_pentester_key)"
  ssh -i "$keyfile" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -p "$DROPLET_SSH_PORT" "$DROPLET_ROOT@$DROPLET_IP" "$@"
}
remote_root_key_scp(){ # args: <src> <dest>
  local keyfile; keyfile="$(get_pentester_key)"
  scp -i "$keyfile" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -P "$DROPLET_SSH_PORT" "$1" "$DROPLET_ROOT@$DROPLET_IP:$2"
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
  *) usage; exit 1 ;;
esac

echo; log "Kali Dropbox Setup: $cmd"
load_conf

# ===================== prereq wizard (once) =====================
if ! donep prereq; then
  ensure_local_ssh_identity

  prompt CLIENT_NAME "Client company name (e.g., Acme123)"
  suggest="$(sanitize_hostname "$CLIENT_NAME")"; [[ -z "$suggest" ]] && suggest="client"
  suggest="${suggest}-linux-vm"
  echo "Suggested hostname: $suggest"
  prompt HOSTNAME "Confirm or enter alternate hostname" "$suggest"
  HOSTNAME="$(sanitize_hostname "$HOSTNAME")"; [[ -z "$HOSTNAME" ]] && { echo "Hostname cannot be empty"; exit 1; }

  echo
  echo "DigitalOcean droplet (password-free bootstrap)"
  prompt DROPLET_IP "Droplet public IP or DNS"
  prompt DROPLET_SSH_PORT "Droplet SSH port" "22"
  prompt DROPLET_ROOT "Droplet root username" "root"
  prompt TUNNEL_USER "Dedicated tunnel username to create on droplet" "tunnel"

  echo
  echo "Reverse SSH settings"
  prompt REVERSE_REMOTE_PORT "Remote port for SSH on droplet" "2222"
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
  read -rp "After setup, remove the pentester key from ROOT on the droplet (others untouched)? (y/n) " yn3
  [[ "${yn3,,}" == "n" ]] && REMOVE_PENTESTER_KEY_FROM_ROOT="no" || REMOVE_PENTESTER_KEY_FROM_ROOT="yes"

  read -rp "Disable SSH password authentication on the droplet after setup? (y/n) " yn4
  [[ "${yn4,,}" == "y" ]] && DISABLE_PASSWORD_AUTH="yes" || DISABLE_PASSWORD_AUTH="no"

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
  echo "Remove pentester key from ROOT after setup: $REMOVE_PENTESTER_KEY_FROM_ROOT"
  echo "Disable SSH password authentication:        $DISABLE_PASSWORD_AUTH"
  echo "------------------"
  echo
  echo "IMPORTANT:"
  echo "  Add the pentester PUBLIC KEY shown above to /root/.ssh/authorized_keys on the droplet now."
  echo "Press Enter when root key login should work; the script will verify and continue."
  read -r _

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

# 4 core tooling
if ! donep step4; then
  log "Installing core tools"
  apt-get update -y
  apt-get install -y \
    git tmux vim jq curl wget unzip ca-certificates \
    build-essential python3 python3-pip python3-venv golang \
    nmap masscan amass crackmapexec \
    feroxbuster gobuster ffuf \
    impacket-scripts responder \
    net-tools dnsutils socat autossh ufw \
    nuclei zaproxy chromium openssh-server htop seclists
  runuser -l pentester -c 'nuclei -update-templates || true'
  systemctl enable ssh; systemctl restart ssh

  if [[ "$ENABLE_RDP" == "yes" ]]; then
    log "Enabling RDP"
    apt-get install -y xrdp xorgxrdp ssl-cert
    id -u xrdp >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin xrdp || true
    adduser xrdp ssl-cert || true
    make-ssl-cert generate-default-snakeoil --force-overwrite || true
    chown root:ssl-cert /etc/ssl/private/ssl-cert-snakeoil.key
    chmod 640 /etc/ssl/private/ssl-cert-snakeoil.key
    sed -i 's/^use_vsock=.*/use_vsock=false/' /etc/xrdp/xrdp.ini
    sed -i 's/^port=.*/port=3389/' /etc/xrdp/xrdp.ini
    echo "startxfce4" > /home/pentester/.xsession
    chown pentester:pentester /home/pentester/.xsession
    systemctl enable --now xrdp xrdp-sesman
    systemctl restart xrdp
  fi

  mark step4
  maybe_prompt_reboot_and_exit
fi

# 5 sshd hardening (local)
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

# 7 droplet bootstrap via ROOT key only
if ! donep step7; then
  log "Verifying root@${DROPLET_IP} key login"
  local_pub="$(get_pentester_pub || true)"
  if [[ -z "${local_pub:-}" ]]; then echo "No local pentester public key found"; exit 1; fi

  # wait until root key login works
  while true; do
    if remote_root_key_ssh true 2>/dev/null; then
      log "Root key login ok."
      break
    fi
    echo "Root key login not working yet. Ensure this line exists in /root/.ssh/authorized_keys on the droplet:"
    cat "$local_pub"
    read -rp "Press Enter to retry root key login..." _
  done

  # seed pentester's known_hosts with the droplet's key
  sudo -u pentester mkdir -p /home/pentester/.ssh
  sudo -u pentester ssh-keyscan -p "$DROPLET_SSH_PORT" "$DROPLET_IP" >> /home/pentester/.ssh/known_hosts || true
  sudo chown pentester:pentester /home/pentester/.ssh/known_hosts
  sudo chmod 600 /home/pentester/.ssh/known_hosts

  log "[Droplet] creating tunnel user and migrating pentester key"
  remote_root_key_ssh "id -u $TUNNEL_USER >/dev/null 2>&1 || useradd -m -s /bin/bash $TUNNEL_USER"
  remote_root_key_ssh "mkdir -p /home/$TUNNEL_USER/.ssh && chmod 700 /home/$TUNNEL_USER/.ssh"
  remote_root_key_scp "$local_pub" "/tmp/pentester_key.pub"
  remote_root_key_ssh "auth='/home/$TUNNEL_USER/.ssh/authorized_keys'; touch \"\$auth\"; \
    grep -qxF \"\$(cat /tmp/pentester_key.pub)\" \"\$auth\" || cat /tmp/pentester_key.pub >> \"\$auth\"; \
    rm -f /tmp/pentester_key.pub; chown -R $TUNNEL_USER:$TUNNEL_USER /home/$TUNNEL_USER/.ssh; chmod 700 /home/$TUNNEL_USER/.ssh; chmod 600 \"\$auth\""

  # verify tunnel login using pentester key
  PKEY="/home/pentester/.ssh/id_ed25519"; [[ -f "$PKEY" ]] || PKEY="/home/pentester/.ssh/id_rsa"
  if sudo -u pentester ssh -i "$PKEY" -o BatchMode=yes -o StrictHostKeyChecking=no \
      -p "$DROPLET_SSH_PORT" "$TUNNEL_USER@$DROPLET_IP" true 2>/dev/null; then
    log "Tunnel user key login verified."
  else
    echo "[ERROR] Could not log in as $TUNNEL_USER via key. Check /home/$TUNNEL_USER/.ssh/authorized_keys on droplet."
    exit 1
  fi

  # optional key removal from root
  if [[ "${REMOVE_PENTESTER_KEY_FROM_ROOT}" == "yes" ]]; then
    log "[Droplet] removing pentester key from ROOT authorized_keys (others untouched)"
    remote_root_key_scp "$local_pub" "/tmp/pk.pub"
    remote_root_key_ssh "R=/root/.ssh/authorized_keys; B=\"\${R}.bak.\$(date +%s)\"; cp -a \"\$R\" \"\$B\" 2>/dev/null || true; \
      awk 'NR==FNR{a[\$0]=1;next}!a[\$0]' /tmp/pk.pub \"\$R\" > \"\${R}.new\"; mv \"\${R}.new\" \"\$R\"; rm -f /tmp/pk.pub; chmod 600 \"\$R\""
  fi

  # optional hardening to key-only and forwarding
  if [[ "${DISABLE_PASSWORD_AUTH}" == "yes" ]]; then
    log "[Droplet] disabling SSH password authentication (key-only)"
    remote_root_key_ssh "CFG=/etc/ssh/sshd_config; cp -a \"\$CFG\" \"\${CFG}.bak.\$(date +%s)\" 2>/dev/null || true; \
      sed -i 's/^#\\?PasswordAuthentication .*/PasswordAuthentication no/' \"\$CFG\"; \
      sed -i 's/^#\\?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication no/' \"\$CFG\"; \
      sed -i 's/^#\\?AllowTcpForwarding .*/AllowTcpForwarding yes/' \"\$CFG\""
    if [[ "$REVERSE_BIND_ADDR" == "0.0.0.0" || "${RDP_BIND_ADDR:-}" == "0.0.0.0" ]]; then
      remote_root_key_ssh "CFG=/etc/ssh/sshd_config; \
        grep -q '^GatewayPorts ' \"\$CFG\" && sed -i 's/^GatewayPorts .*/GatewayPorts clientspecified/' \"\$CFG\" || \
        echo 'GatewayPorts clientspecified' >> \"\$CFG\""
    fi
    remote_root_key_ssh "systemctl restart ssh"
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
     -o "StrictHostKeyChecking=accept-new" -o "UserKnownHostsFile=${PENTESTER_HOME}/.ssh/known_hosts"
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
After=network-online.target ssh.service
Wants=network-online.target
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

# 9 validation helper
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
  chk "xrdp active" systemctl is-active --quiet xrdp
  chk "xrdp-sesman active" systemctl is-active --quiet xrdp-sesman
  chk "RDP port 3389 listening" bash -c 'ss -lnt | grep -q ":3389 "'
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
  [[ "${EXPOSE_RDP_VIA_DROPLET}" == "yes" ]] && echo "RDP reverse: ${RDP_BIND_ADDR}:${RDP_REMOTE_PORT} -> this host 3389"
fi
echo "From the droplet shell: ssh -p ${REVERSE_REMOTE_PORT} pentester@127.0.0.1"
echo "Validate any time: /usr/local/bin/validate_kali.sh"
