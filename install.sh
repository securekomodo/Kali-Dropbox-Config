#!/usr/bin/env bash
set -euo pipefail

require_root(){ [[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }; }
require_root

LOGFILE="/var/log/kali_dropbox_setup.log"
exec > >(tee -a "$LOGFILE") 2>&1

STATE_DIR="/var/lib/kali-dropbox-setup"
CONF_DIR="/etc/redline"
CONF_FILE="${CONF_DIR}/dropbox.conf"
mkdir -p "$STATE_DIR" "$CONF_DIR"; chmod 700 "$CONF_DIR"

mark(){ touch "${STATE_DIR}/$1.done"; }
donep(){ [[ -f "${STATE_DIR}/$1.done" ]]; }

sanitize_hostname(){ echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/-+/-/g; s/^-+//; s/-+$//'; }
prompt(){ local v="$1" m="$2" d="${3:-}"; if [[ -n "${!v:-}" ]]; then return; fi; read -rp "$m${d:+ [$d]}: " x; [[ -z "$x" && -n "$d" ]] && x="$d"; declare -g "$v"="$x"; }
prompt_secret(){ local v="$1" m="$2"; if [[ -n "${!v:-}" ]]; then return; fi; read -rsp "$m: " x; echo; declare -g "$v"="$x"; }

need_reboot(){
  [[ -f /var/run/reboot-required ]] && return 0
  command -v needrestart >/dev/null 2>&1 && needrestart -b -r a 2>/dev/null | grep -qi "reboot is needed" && return 0
  return 1
}
schedule_resume(){
  local self; self="$(realpath "$0")"
  cat >/etc/systemd/system/kali-setup-resume.service <<EOF
[Unit]
Description=Resume Kali Dropbox Setup
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=${self} --resume
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload; systemctl enable --now kali-setup-resume.service
}
clear_resume(){ systemctl disable --now kali-setup-resume.service >/dev/null 2>&1 || true; rm -f /etc/systemd/system/kali-setup-resume.service || true; systemctl daemon-reload; }

save_conf(){
  cat >"$CONF_FILE" <<EOF
CLIENT_NAME='${CLIENT_NAME}'
HOSTNAME='${HOSTNAME}'
# droplet bootstrap (used once)
DROPLET_ROOT='${DROPLET_ROOT}'
DROPLET_PW='${DROPLET_PW}'
DROPLET_IP='${DROPLET_IP}'
DROPLET_SSH_PORT='${DROPLET_SSH_PORT}'
# dedicated tunnel user created remotely
TUNNEL_USER='${TUNNEL_USER}'
# reverse tunnels
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

echo; echo "=== Kali Dropbox Setup $(date '+%F %T') ==="
load_conf

# ---------------- PREREQ WIZARD ----------------
if ! donep prereq; then
  prompt CLIENT_NAME "Client company name (e.g., Acme123)"
  local_suggest="$(sanitize_hostname "$CLIENT_NAME")"; [[ -z "$local_suggest" ]] && local_suggest="client"
  local_suggest="${local_suggest}-linux-vm"
  echo "Suggested hostname: $local_suggest"
  prompt HOSTNAME "Confirm or enter alternate hostname" "$local_suggest"
  HOSTNAME="$(sanitize_hostname "$HOSTNAME")"; [[ -z "$HOSTNAME" ]] && { echo "Hostname cannot be empty"; exit 1; }

  echo; echo "DigitalOcean droplet bootstrap (one time, will switch to keys and disable root password afterward)"
  prompt DROPLET_IP "Droplet public IP or DNS"
  prompt DROPLET_SSH_PORT "Droplet SSH port" "22"
  prompt DROPLET_ROOT "Root username on droplet" "root"
  prompt_secret DROPLET_PW "Root password on droplet (will be used once to set up keys)"
  prompt TUNNEL_USER "Dedicated tunnel username to create on droplet" "tunnel"

  echo; echo "Reverse SSH"
  prompt REVERSE_REMOTE_PORT "Remote port for SSH on droplet (e.g., 20022)" "20022"
  echo "Bind address options on droplet: localhost (safe, only reachable from droplet) or 0.0.0.0 (exposed; use firewall)"
  prompt REVERSE_BIND_ADDR "Bind address for SSH reverse port" "localhost"

  echo; read -rp "Enable RDP on this box? (y/n) " yn; [[ "${yn,,}" == "y" ]] && ENABLE_RDP="yes" || ENABLE_RDP="no"
  EXPOSE_RDP_VIA_DROPLET="no"; RDP_REMOTE_PORT=""; RDP_BIND_ADDR="localhost"
  if [[ "$ENABLE_RDP" == "yes" ]]; then
    read -rp "Also expose RDP via droplet? (y/n) " yn2
    if [[ "${yn2,,}" == "y" ]]; then
      EXPOSE_RDP_VIA_DROPLET="yes"
      prompt RDP_REMOTE_PORT "Remote port for RDP on droplet" "23389"
      echo "Bind address for RDP on droplet: localhost or 0.0.0.0"
      prompt RDP_BIND_ADDR "Bind address for RDP reverse port" "localhost"
    fi
  fi

  echo; echo "----- Review -----"
  echo "Client:            $CLIENT_NAME"
  echo "Hostname:          $HOSTNAME"
  echo "Droplet root user: $DROPLET_ROOT@$DROPLET_IP:$DROPLET_SSH_PORT"
  echo "Tunnel user:       $TUNNEL_USER"
  echo "SSH reverse:       ${REVERSE_BIND_ADDR}:${REVERSE_REMOTE_PORT} -> localhost:22"
  if [[ "$ENABLE_RDP" == "yes" ]]; then
    echo "RDP local:         3389 enabled"
    [[ "$EXPOSE_RDP_VIA_DROPLET" == "yes" ]] && echo "RDP reverse:       ${RDP_BIND_ADDR}:${RDP_REMOTE_PORT} -> localhost:3389"
  fi
  echo "------------------"
  read -rp "Proceed? (y/n) " ok; [[ "${ok,,}" == "y" ]] || { echo "Aborted."; exit 1; }

  save_conf; mark prereq
fi

load_conf

# ---------------- LOCAL PREP ----------------
if ! donep step1; then
  hostnamectl set-hostname "$HOSTNAME"
  grep -q "$HOSTNAME" /etc/hosts || echo "127.0.1.1 $HOSTNAME" >> /etc/hosts
  timedatectl set-ntp true || true
  mark step1
fi

if ! donep step2; then
  if ! id pentester &>/dev/null; then
    echo "Creating user pentester"
    useradd -m -s /bin/bash pentester
    echo "Set password for pentester (used for console and RDP)"
    passwd pentester
    usermod -aG sudo pentester
  fi
  echo "pentester ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/010_pentester_nopasswd
  chmod 440 /etc/sudoers.d/010_pentester_nopasswd
  mark step2
fi

if ! donep step3; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get -o Dpkg::Options::="--force-confnew" dist-upgrade -y
  apt-get autoremove -y; apt-get autoclean -y
  apt-get install -y needrestart || true
  if need_reboot; then echo "Reboot required; resuming after boot"; schedule_resume; reboot; exit 0; fi
  mark step3
fi

if ! donep step4; then
  apt-get update -y
  apt-get install -y git tmux vim jq curl wget unzip ca-certificates \
    build-essential python3 python3-pip python3-venv golang \
    nmap masscan amass crackmapexec feroxbuster gobuster ffuf \
    impacket-scripts bloodhound python3-bloodhound responder \
    net-tools dnsutils socat autossh sshpass ufw \
    nuclei seclists zaproxy chromium openssh-server htop xrdp xorgxrdp || true
  runuser -l pentester -c 'nuclei -update-templates || true'
  systemctl enable ssh; systemctl restart ssh
  mark step4
fi

if ! donep step5; then
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

if ! donep step6; then
  if [[ "${ENABLE_RDP}" == "yes" ]]; then
    adduser xrdp ssl-cert || true
    systemctl enable xrdp; systemctl restart xrdp
    su - pentester -c 'echo "export DESKTOP_SESSION=kali-xfce" > ~/.xsessionrc'
  fi
  mark step6
fi

# Ensure local key exists for autossh
if ! donep step7; then
  runuser -l pentester -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh'
  if ! runuser -l pentester -c 'test -f ~/.ssh/id_ed25519'; then
    runuser -l pentester -c 'ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519 -C "kali-dropbox"'
  fi
  mark step7
fi

# ---------------- DROPLET BOOTSTRAP (one time via root password) ----------------
remote_ssh_root(){ sshpass -p "$DROPLET_PW" ssh -o StrictHostKeyChecking=no -p "$DROPLET_SSH_PORT" "$DROPLET_ROOT@$DROPLET_IP" "$@"; }
remote_scp_root(){ SSH_ASKPASS=/bin/true sshpass -p "$DROPLET_PW" scp -o StrictHostKeyChecking=no -P "$DROPLET_SSH_PORT" "$1" "$DROPLET_ROOT@$DROPLET_IP:$2"; }

if ! donep droplet_bootstrap; then
  echo "[Droplet] creating $TUNNEL_USER, installing key, and hardening sshd"
  PUBKEY_LOCAL="/home/pentester/.ssh/id_ed25519.pub"
  [[ -f "$PUBKEY_LOCAL" ]] || { echo "Missing $PUBKEY_LOCAL"; exit 1; }

  remote_ssh_root "id -u $TUNNEL_USER >/dev/null 2>&1 || useradd -m -s /bin/bash $TUNNEL_USER"
  remote_ssh_root "mkdir -p /home/$TUNNEL_USER/.ssh && chmod 700 /home/$TUNNEL_USER/.ssh && chown -R $TUNNEL_USER:$TUNNEL_USER /home/$TUNNEL_USER/.ssh"
  remote_scp_root "$PUBKEY_LOCAL" "/home/$TUNNEL_USER/.ssh/authorized_keys"
  remote_ssh_root "chown $TUNNEL_USER:$TUNNEL_USER /home/$TUNNEL_USER/.ssh/authorized_keys && chmod 600 /home/$TUNNEL_USER/.ssh/authorized_keys"

  # sshd hardening on droplet
  DROPLET_SSHD_EDIT='
    set -e
    CFG="/etc/ssh/sshd_config"
    cp "$CFG" "${CFG}.bak.$(date +%s)"
    sed -i "s/^#\?PermitRootLogin .*/PermitRootLogin no/" "$CFG"
    sed -i "s/^#\?PasswordAuthentication .*/PasswordAuthentication no/" "$CFG"
    sed -i "s/^#\?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication no/" "$CFG"
    sed -i "s/^#\?AllowTcpForwarding .*/AllowTcpForwarding yes/" "$CFG"
    # Keep GatewayPorts default (no). If you chose 0.0.0.0 binds, allow clientspecified
  '
  if [[ "$REVERSE_BIND_ADDR" == "0.0.0.0" || "$RDP_BIND_ADDR" == "0.0.0.0" ]]; then
    DROPLET_SSHD_EDIT+='
      grep -q "^GatewayPorts " "$CFG" && sed -i "s/^GatewayPorts .*/GatewayPorts clientspecified/" "$CFG" || echo "GatewayPorts clientspecified" >> "$CFG"
    '
  fi
  DROPLET_SSHD_EDIT+=$'\n''systemctl restart ssh'

  remote_ssh_root "bash -lc '$DROPLET_SSHD_EDIT'"

  echo "[Droplet] sshd set to key-only, root login disabled"
  mark droplet_bootstrap
fi

# ---------------- AUTOSSH SERVICE (SSH and optional RDP) ----------------
if ! donep autossh; then
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
SSH_CMD=(/usr/bin/autossh -M 0 -N
  -o "ServerAliveInterval=30" -o "ServerAliveCountMax=3" -o "ExitOnForwardFailure=yes"
  -i "${PENTESTER_HOME}/.ssh/id_ed25519")
# SSH reverse
SSH_CMD+=(-R "${REVERSE_BIND_ADDR}:${REVERSE_REMOTE_PORT}:localhost:${LOCAL_SSH_PORT}")
# Optional RDP reverse
if [[ "${EXPOSE_RDP_VIA_DROPLET}" == "yes" && -n "${RDP_REMOTE_PORT}" ]]; then
  SSH_CMD+=(-R "${RDP_BIND_ADDR}:${RDP_REMOTE_PORT}:localhost:${LOCAL_RDP_PORT}")
fi
SSH_CMD+=(-p "${DROPLET_SSH_PORT}" "${TUNNEL_USER}@${DROPLET_IP}")
exec "${SSH_CMD[@]}"
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
  mark autossh
fi

# ---------------- VALIDATION AND FINISH ----------------
if ! donep validate; then
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
if systemctl is-enabled xrdp >/dev/null 2>&1; then chk "xrdp active" systemctl is-active --quiet xrdp; fi
echo "Done. Errors: $err"; exit $err
EOF
  chmod +x /usr/local/bin/validate_kali.sh
  mark validate
fi

# Final tidy and optional reboot
if ! donep final; then
  apt-get update -y
  apt-get -o Dpkg::Options::="--force-confnew" dist-upgrade -y || true
  apt-get autoremove -y; apt-get autoclean -y
  if need_reboot; then echo "Reboot required to finish; resuming after boot"; schedule_resume; reboot; exit 0; fi
  mark final
fi

clear_resume
echo
echo "Setup complete."
echo "SSH reverse on droplet: ${REVERSE_BIND_ADDR}:${REVERSE_REMOTE_PORT} -> this host 22"
if [[ "${ENABLE_RDP}" == "yes" ]]; then
  echo "RDP enabled locally on 3389 for user 'pentester'."
  [[ "${EXPOSE_RDP_VIA_DROPLET}" == "yes" ]] && echo "RDP reverse on droplet: ${RDP_BIND_ADDR}:${RDP_REMOTE_PORT} -> this host 3389"
fi
echo "From the droplet itself: ssh -p ${REVERSE_REMOTE_PORT} pentester@127.0.0.1"
[[ "${REVERSE_BIND_ADDR}" == "0.0.0.0" ]] && echo "If exposed on 0.0.0.0, restrict inbound with the cloud firewall."
echo "Validate any time: /usr/local/bin/validate_kali.sh"
