#!/usr/bin/env bash
# Kali Linux Setup Script
# Fresh install: sets hostname, creates pentester user, updates system, installs Nuclei, configures SSH, downloads and installs Nessus Pro, disables suspend, and sets up validation

# Ensure running as root before any operations
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root. Exiting."
  exit 1
fi

LOGFILE="/var/log/setup_kali.log"
exec > >(tee -a "$LOGFILE") 2>&1

echo -e "\n============================"
echo "Kali Linux Setup - $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================"

# Set hostname
echo "[INFO] Setting hostname to pentest-vm..."
hostnamectl set-hostname pentest-vm
if ! grep -q "pentest-vm" /etc/hosts; then
  echo "127.0.1.1 pentest-vm" >> /etc/hosts
fi

# Create pentester user
echo "[INFO] Creating user 'pentester'..."
if ! id pentester &>/dev/null; then
  read -s -p "Enter password for pentester: " USERPASS; echo
  useradd -m -s /bin/bash pentester
  echo "pentester:$USERPASS" | chpasswd
  usermod -aG sudo pentester
  echo "[INFO] User 'pentester' created and added to sudo."
else
  echo "[INFO] User 'pentester' already exists."
fi

# Update and upgrade system
echo "[INFO] Updating package lists..."
apt-get update -y

echo "[INFO] Upgrading installed packages..."
apt-get dist-upgrade -y

# Clean up
echo "[INFO] Cleaning up..."
apt-get autoremove -y && apt-get autoclean -y

# Install and configure Nuclei
echo "[INFO] Installing Nuclei scanner..."
if ! command -v nuclei &> /dev/null; then
  apt-get install -y nuclei
  echo "[INFO] Nuclei installed."
else
  echo "[INFO] Nuclei already present."
fi

echo "[INFO] Updating Nuclei templates..."
nuclei -update-templates || echo "[WARN] Failed to update templates."

echo "[INFO] Nuclei setup complete."

# Download and install Nessus Pro
echo "[INFO] Downloading Nessus Pro installer..."
NESSUS_URL="https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.8.4-debian10_amd64.deb"
curl -L "$NESSUS_URL" --output "/tmp/Nessus.deb" || { echo "[ERROR] Failed to download Nessus Pro."; }

echo "[INFO] Installing Nessus Pro..."
dpkg -i /tmp/Nessus.deb || { echo "[ERROR] dpkg install failed. Attempting fix..."; apt-get install -f -y; }
systemctl enable nessusd
systemctl start nessusd
echo "[INFO] Nessus Pro installed and service started."

# Enable and configure SSH
echo "[INFO] Ensuring OpenSSH Server is installed and secured..."
if ! dpkg -l | grep -q openssh-server; then
  apt-get install -y openssh-server
fi
systemctl enable ssh
systemctl start ssh
# Harden SSH: disable root login and enforce protocol 2
sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*Protocol .*/Protocol 2/' /etc/ssh/sshd_config
systemctl reload ssh

echo "[INFO] SSH configured."

# Disable suspend/hibernate to keep VM alive
echo "[INFO] Masking suspend and hibernate targets..."
for t in sleep.target suspend.target hibernate.target hybrid-sleep.target; do
  systemctl mask "$t"
done

echo "[INFO] Suspend/hibernate disabled."

# Create validation script
VALIDATE_PATH="/usr/local/bin/validate_kali.sh"
echo "[INFO] Creating validation script at $VALIDATE_PATH..."
cat << 'EOF' > "$VALIDATE_PATH"
#!/usr/bin/env bash
# Validate key Kali settings
errors=0

# Hostname check
echo -n "[VALIDATE] Hostname: "
[ "$(hostname)" = "pentest-vm" ] && echo "correct" || { echo "$(hostname)"; errors=1; }

# User existence
echo -n "[VALIDATE] User 'pentester': "
id pentester &>/dev/null && echo "exists" || { echo "missing"; errors=1; }

# SSH service
echo -n "[VALIDATE] SSH service: "
systemctl is-active --quiet ssh && echo "running" || { echo "not running"; errors=1; }

# Nuclei
echo -n "[VALIDATE] Nuclei: "
command -v nuclei &>/dev/null && echo "installed" || { echo "missing"; errors=1; }

echo -n "[VALIDATE] Nuclei templates: "
[ -d "$HOME/.nuclei-templates" ] && echo "present" || { echo "absent"; errors=1; }

# Nessus Pro
echo -n "[VALIDATE] Nessus service: "
if systemctl is-active --quiet nessusd; then echo "running"; else echo "not running"; errors=1; fi

# Suspend targets
echo -n "[VALIDATE] Suspend targets masked: "
for t in sleep.target suspend.target hibernate.target hybrid-sleep.target; do
  systemctl is-masked --quiet "$t" || { echo "$t not masked"; errors=1; }
done

# UFW status
echo -n "[VALIDATE] UFW: "
if command -v ufw &>/dev/null; then ufw status | grep -q "inactive" && echo "inactive" || { echo "active"; errors=1; }; fi

echo "Validation complete. Errors: $errors"
EOF
chmod +x "$VALIDATE_PATH"

# Schedule validation on reboot
echo "[INFO] Scheduling validation on reboot via cron..."
(crontab -l 2>/dev/null; echo "@reboot root $VALIDATE_PATH >> /var/log/validate_kali.log 2>&1") | crontab -

# Final message
echo -e "\nSetup complete. Please reboot the system to apply all changes."
