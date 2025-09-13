#!/usr/bin/env bash
# Kali Dropbox Setup with prereq wizard
# Standard user for remote ops: "pentester"
# Safe to re-run. Handles reboot and resume.

set -euo pipefail

require_root(){ [[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }; }
require_root

LOGFILE="/var/log/kali_dropbox_setup.log"
exec > >(tee -a "$LOGFILE") 2>&1

STATE_DIR="/var/lib/kali-dropbox-setup"
CONF_DIR="/etc/redline"
CONF_FILE="${CONF_DIR}/dropbox.conf"
mkdir -p "$STATE_DIR" "$CONF_DIR"
chmod 700 "$CONF_DIR"

mark(){ touch "${STATE_DIR}/$1.done"; }
donep(){ [[ -f "${STATE_DIR}/$1.done" ]]; }

sanitize_hostname(){
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/-+/-/g; s/^-+//; s/-+$//'
}

prompt(){
  local var="$1" msg="$2" def="${3:-}"
  if [[ -n "${!var:-}" ]]; then return 0; fi
  read -rp "$msg${def:+ [$def]}: " val
  [[ -z "$val" && -n "$def" ]] && val="$def"
  declare -g "$var"="$val"
}

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
  systemctl daemon-reload
  systemctl enable --now kali-setup-resume.service
}

clear_resume(){
  systemctl disable --now kali-setup-resume.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/kali-setup-resume.service || true
  systemctl daemon-reload
}

save_conf(){
  cat >"$CONF_FILE" <<EOF
CLIENT_NAME='${CLIENT_NAME}'
HOSTNAME='${HOSTNAME}'
DROPLET_USER='${DROPLET_USER}'
DROPLET_IP='${DROPLET_IP}'
DROPLET_SSH_PORT='${DROPLET_SSH_PORT}'
REVERSE_REMOTE_PORT='${REVERSE_REMOTE_PORT}'
ENABLE_RDP='${ENABLE_RDP}'
EXPOSE_RDP_VIA_DROPLET='${EXPOSE_RDP_VIA_DROPLET}'
RDP_REMOTE_PORT='${RDP_REMOTE_PORT}'
EOF
  chmod 600 "$CONF_FILE"
}
load_conf(){ [[ -f "$CONF_FILE" ]] && source "$CONF_FILE" || true; }

echo; echo "=== Kali Dropbox Setup $(date '+%F %T') ==="
load_conf

# -------- Prereq wizard (before any changes) --------
if ! donep prereq; then
  prompt CLIENT_NAME "Client company name (e.g., Acme123)"
  suggest="$(sanitize_hostname "$CLIENT_NAME")"
  [[ -z "$suggest" ]] && suggest="client"
  suggest="${suggest}-linux-vm"
  echo "Suggested hostname: $suggest"
  prompt HOSTNAME "Confirm or enter alternate hostname" "$suggest"
  HOSTNAME="$(sanitize_hostname "$HOSTNAME")"
  [[ -z "$HOSTNAME" ]] && { echo "Hostname cannot be empty"; exit 1; }

  echo; echo "DigitalOcean reverse tunnel settings"
  prompt DROPLET_USER "Droplet SSH user"
  prompt DROPLET_IP "Droplet public IP or DNS"
  prompt DROPLET_SSH_PORT "Droplet SSH port" "22"
  prompt REVERSE_REMOTE_PORT "Remote port to expose this box SSH on the droplet" "20022"

  echo; read -rp "Enable RDP on this box? (y/n) " yn
  [[ "${yn,,}" == "y" ]] && ENABLE_RDP="yes" || ENABLE_RDP="no"
  EXPOSE_RDP_VIA_DROPLET="no"; RDP_REMOTE_PORT=""
  if [[ "$ENABLE_RDP" == "yes" ]]; then
    read -rp "Also expose RDP through the droplet? (y/n) " yn2
    if [[ "${yn2,,}" == "y" ]]; then
      EXPOSE_RDP_VIA_DROPLET="yes"
      prompt RDP_REMOTE_PORT "Remote port for RDP on droplet (3389 recommended only if firewall restricted)" "23389"
    fi
  fi

  echo; echo "----- Review -----"
  echo "Client:            $CLIENT_NAME"
  echo "Hostname:          $HOSTNAME"
  echo "Droplet:           ${DROPLET_USER}@${DROPLET_IP}:${DROPLET_SSH_PORT}"
  echo "Reverse SSH port:  $REVERSE_REMOTE_PORT"
  echo "Enable RDP:        $ENABLE_RDP"
  echo "Expose RDP via DO: $EXPOSE_RDP_VIA_DROPLET ${RDP_REMOTE_PORT:+(port $RDP_REMOTE_PORT)}"
  echo "------------------"
  read -rp "Proceed with these settings? (y/n) " ok
  [[ "${ok,,}" == "y" ]] || { echo "Aborted before making changes."; exit 1; }

  save_conf
  mark prereq
fi

# Reload for resume path
load_conf

# -------- System changes begin --------

# 1 hostname and time
if ! donep step1; then
  hostnamectl set-hostname "$HOSTNAME"
  grep -q "$HOSTNAME" /etc/hosts || echo "127.0.1.1 ${HOSTNAME}" >> /etc/hosts
  timedatectl set-ntp true || true
  mark step1
fi

# 2 ensure pentester user
if ! donep step2; then
  if ! id pentester &>/dev/null; then
    echo "Creating user pentester for standard remote operations"
    useradd -m -s /bin/bash pentester
    echo "Set password for pentester (used for console and RDP if enabled)"
    passwd pentester
    usermod -aG sudo pentester
  else
    echo "User pentester already exists"
  fi
  echo "pentester ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/010_pentester_nopasswd
  chmod 440 /etc/sudoers.d/010_pentester_nopasswd
  mark step2
fi

# 3 update and reboot if needed
if ! donep step3; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get -o Dpkg::Options::="--force-confnew" dist-upgrade -y
  apt-get autoremove -y
  apt-get autoclean -y
  apt-get install -y needrestart || true
  if need_reboot; then
    echo "Reboot required. Scheduling resume and rebooting."
    schedule_resume
    reboot
    exit 0
  fi
  mark step3
fi

# 4 core tooling
if ! donep step4; then
  apt-get update -y
  apt-get install -y \
    git tmux vim jq curl wget unzip ca-certificates \
    build-essential python3 python3-pip python3-venv golang \
    nmap masscan amass crackmapexec \
    feroxbuster gobuster ffuf \
    impacket-scripts bloodhound python3-bloodhound \
    responder net-tools dnsutils socat autossh \
    nuclei seclists zaproxy chromium \
    openssh-server htop
  runuser -l pentester -c 'nuclei -update-templates || true'
  systemctl enable ssh
  systemctl restart ssh
  mark step4
fi

# 5 SSH server baseline
if ! donep step5; then
  sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  sed -i 's/^#\?KbdInteractiveAuthentication .*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
  sed -i 's/^#\?PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
  grep -q '^ClientAliveInterval' /etc/ssh/sshd_config || echo 'ClientAliveInterval 60' >> /etc/ssh/sshd_config
  grep -q '^ClientAliveCountMax' /etc/ssh/sshd_config || echo 'ClientAliveCountMax 3' >> /etc/ssh/sshd_config
  systemctl restart ssh
  mark step5
fi

# 6 disable sleep
if ! donep step6; then
  for t in sleep.target suspend.target hibernate.target hybrid-sleep.target; do
    systemctl mask "$t" || true
  done
  mark step6
fi

# 7 optional RDP install and enable
if ! donep step7; then
  if [[ "$ENABLE_RDP" == "yes" ]]; then
    apt-get install -y xrdp xorgxrdp
    adduser xrdp ssl-cert || true
    systemctl enable xrdp
    systemctl restart xrdp
    # ensure pentester will use Xorg session
    su - pentester -c 'mkdir -p ~/.xsessionrc.d; echo "export DESKTOP_SESSION=kali-xfce" > ~/.xsessionrc'
    echo "RDP enabled. Connect to ${HOSTNAME}:3389 as user pentester."
  else
    echo "RDP not enabled."
  fi
  mark step7
fi

# 8 SSH key for pentester and droplet details
if ! donep step8; then
  runuser -l pentester -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh'
  if ! runuser -l pentester -c 'test -f ~/.ssh/id_ed25519'; then
    runuser -l pentester -c 'ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519 -C "kali-dropbox"'
    echo "Created SSH key at /home/pentester/.ssh/id_ed25519"
  fi

  echo; echo "Add this public key to the droplet authorized_keys:"
  echo "----- copy start -----"
  cat /home/pentester/.ssh/id_ed25519.pub
  echo "----- copy end -----"

  read -rp "Attempt ssh-copy-id now? (y/n) " scpy
  if [[ "${scpy,,}" == "y" ]]; then
    apt-get install -y sshpass || true
    runuser -l pentester -c "ssh-copy-id -i ~/.ssh/id_ed25519.pub -p ${DROPLET_SSH_PORT} ${DROPLET_USER}@${DROPLET_IP}" || echo "ssh-copy-id did not complete. Add the key manually if needed."
  fi
  mark step8
fi

# 9 autossh reverse tunnel service (SSH, and optional RDP)
if ! donep step9; then
  cat >/etc/autossh-reverse-tunnel.conf <<EOF
AUTOSSH_GATETIME=0
AUTOSSH_PORT=0
DROPLET_USER="${DROPLET_USER}"
DROPLET_IP="${DROPLET_IP}"
DROPLET_SSH_PORT="${DROPLET_SSH_PORT}"
REVERSE_REMOTE_PORT="${REVERSE_REMOTE_PORT}"
RDP_REMOTE_PORT="${RDP_REMOTE_PORT:-}"
EXPOSE_RDP_VIA_DROPLET="${EXPOSE_RDP_VIA_DROPLET}"
LOCAL_SSH_PORT="22"
LOCAL_RDP_PORT="3389"
PENTESTER_HOME="/home/pentester"
EOF
  chmod 600 /etc/autossh-reverse-tunnel.conf

  cat >/usr/local/bin/start-reverse-tunnel.sh <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
source /etc/autossh-reverse-tunnel.conf
args=(-M 0 -N -o "ServerAliveInterval=30" -o "ServerAliveCountMax=3" -o "ExitOnForwardFailure=yes"
      -i "${PENTESTER_HOME}/.ssh/id_ed25519"
      -R "${REVERSE_REMOTE_PORT}:localhost:${LOCAL_SSH_PORT}")
if [[ "${EXPOSE_RDP_VIA_DROPLET}" == "yes" && -n "${RDP_REMOTE_PORT}" ]]; then
  args+=(-R "${RDP_REMOTE_PORT}:localhost:${LOCAL_RDP_PORT}")
fi
args+=(-p "${DROPLET_SSH_PORT}" "${DROPLET_USER}@${DROPLET_IP}")
exec /usr/bin/autossh "${args[@]}"
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
  mark step9
fi

# 10 validation helper
if ! donep step10; then
  cat >/usr/local/bin/validate_kali.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
err=0; chk(){ printf "%-40s" "$1"; shift; if "$@"; then echo ok; else echo fail; err=1; fi; }
chk "Hostname set" bash -c '[[ -n "$(hostname)" ]]'
chk "User pentester exists" id pentester
chk "SSHD active" systemctl is-active --quiet ssh
chk "autossh active" systemctl is-active --quiet autossh-reverse-tunnel.service
chk "nmap present" command -v nmap >/dev/null
chk "nuclei present" command -v nuclei >/dev/null
if systemctl is-enabled xrdp >/dev/null 2>&1; then
  chk "xrdp active" systemctl is-active --quiet xrdp
fi
echo "Done. Errors: $err"; exit $err
EOF
  chmod +x /usr/local/bin/validate_kali.sh
  mark step10
fi

# 11 final tidy and optional reboot
if ! donep step11; then
  apt-get update -y
  apt-get -o Dpkg::Options::="--force-confnew" dist-upgrade -y || true
  apt-get autoremove -y
  apt-get autoclean -y
  if need_reboot; then
    echo "Reboot required. Scheduling resume."
    schedule_resume
    reboot
    exit 0
  fi
  mark step11
fi

clear_resume
echo
echo "Setup complete."
echo "SSH reverse port on droplet: ${REVERSE_REMOTE_PORT}"
if [[ "${ENABLE_RDP}" == "yes" ]]; then
  echo "RDP enabled locally on 3389 as user 'pentester'."
  [[ "${EXPOSE_RDP_VIA_DROPLET}" == "yes" ]] && echo "RDP also exposed on droplet port ${RDP_REMOTE_PORT}."
fi
echo "From droplet: ssh -p ${REVERSE_REMOTE_PORT} pentester@127.0.0.1"
echo "Validate: /usr/local/bin/validate_kali.sh"
