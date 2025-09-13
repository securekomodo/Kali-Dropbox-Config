#!/usr/bin/env bash
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

echo "[*] verify services"
systemctl enable ssh
systemctl enable autossh-reverse-tunnel.service

echo "[*] ensure autossh comes up with networking"
sed -i 's/^After=.*/After=network-online.target ssh.service/' /etc/systemd/system/autossh-reverse-tunnel.service
sed -i 's/^Wants=.*/Wants=network-online.target/' /etc/systemd/system/autossh-reverse-tunnel.service
systemctl daemon-reload

echo "[*] lock in client config"
test -s /etc/redline/dropbox.conf || { echo "missing /etc/redline/dropbox.conf"; exit 1; }
chown root:root /etc/redline/dropbox.conf
chmod 600 /etc/redline/dropbox.conf

echo "[*] allow service to read tunnel config"
chown root:pentester /etc/autossh-reverse-tunnel.conf
chmod 640 /etc/autossh-reverse-tunnel.conf

echo "[*] keep pentester keys & authorized_keys intact"
chown -R pentester:pentester /home/pentester/.ssh
chmod 700 /home/pentester/.ssh
chmod 600 /home/pentester/.ssh/* || true

echo "[*] pre-seed known_hosts for pentester"
. /etc/autossh-reverse-tunnel.conf
sudo -u pentester mkdir -p /home/pentester/.ssh
sudo -u pentester ssh-keyscan -p "$DROPLET_SSH_PORT" "$DROPLET_IP" >> /home/pentester/.ssh/known_hosts || true
chown pentester:pentester /home/pentester/.ssh/known_hosts
chmod 600 /home/pentester/.ssh/known_hosts

echo "[*] headless friendly boot (keeps xrdp working)"
systemctl set-default multi-user.target

echo "[*] trim & clean"
apt-get -y autoremove || true
apt-get -y autoclean || true
apt-get -y clean || true
journalctl --vacuum-time=2d || true
rm -rf /var/tmp/* /tmp/*

echo "[*] unique identity on first boot"
rm -f /etc/ssh/ssh_host_*key*
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -sf /etc/machine-id /var/lib/dbus/machine-id

echo "[*] wipe history and caches"
history -c || true
rm -f /root/.bash_history /home/pentester/.bash_history || true

echo "[*] final sync & poweroff"
sync
systemctl poweroff
