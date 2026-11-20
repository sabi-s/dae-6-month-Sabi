#!/bin/bash
# HVMC-App-VM01 host hardening (Ubuntu 24.04 LTS)
# Horizon Valley Medical Center - Cloud Infrastructure Security
# Author: Sabitha S Karanavar
#
# Runs ON the VM (pushed by run_part1.sh through Azure Run Command, as root).
# Idempotent: safe to run more than once.
#   1. Automated patching  - unattended-upgrades (daily security updates, auto-reboot 03:30)
#   2. Host firewall       - UFW default-deny; SSH only from Bastion subnet, 8080 only from Web subnet
#   3. Secure SSH          - key-only, no root, AllowUsers, modern crypto, banner, fail2ban
#   4. Kernel/network sysctl baseline
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

BASTION_SUBNET="10.0.4.0/26"
WEB_SUBNET="10.0.1.0/24"
ADMIN_USER="hvmcadmin"

echo "== [0] packages"
apt-get update -q
apt-get install -y -q unattended-upgrades apt-listchanges ufw fail2ban python3-systemd needrestart >/dev/null
apt-get upgrade -y -q >/dev/null          # start from a fully patched baseline

# ---------------------------------------------------------------- 1. automated patching
echo "== [1] automated patching (unattended-upgrades)"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
cat > /etc/apt/apt.conf.d/52hvmc-unattended-upgrades <<'EOF'
// HVMC policy: security pocket + ESM applied daily, reboot in the 03:30 maintenance window
Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
        "${distro_id}ESMApps:${distro_codename}-apps-security";
        "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:30";
Unattended-Upgrade::SyslogEnable "true";
EOF
mkdir -p /etc/needrestart/conf.d
echo "\$nrconf{restart} = 'a';   # restart services using patched libraries automatically" > /etc/needrestart/conf.d/50-hvmc.conf
systemctl enable --now unattended-upgrades apt-daily.timer apt-daily-upgrade.timer >/dev/null

# ---------------------------------------------------------------- 2. host firewall
echo "== [2] host firewall (UFW)"
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed
ufw limit proto tcp from "$BASTION_SUBNET" to any port 22 comment 'SSH from Azure Bastion only (rate-limited)'
ufw allow proto tcp from "$WEB_SUBNET" to any port 8080 comment 'App traffic from Web tier only'
ufw logging medium
ufw --force enable

# ---------------------------------------------------------------- 3. secure SSH
echo "== [3] secure SSH"
cat > /etc/issue.net <<'EOF'
***************************************************************************
 Horizon Valley Medical Center - AUTHORISED USE ONLY
 This system processes electronic protected health information (ePHI).
 All activity is logged and monitored. Unauthorised access is prohibited
 and may be reported to law enforcement (HIPAA 45 CFR 164.312).
***************************************************************************
EOF
# 10- sorts before cloud-init's 50- file; sshd uses the first value it reads.
cat > /etc/ssh/sshd_config.d/10-hvmc-hardening.conf <<EOF
# HVMC SSH hardening - CIS Ubuntu 24.04 section 5.1 aligned
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers $ADMIN_USER
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
PermitUserEnvironment no
HostbasedAuthentication no
IgnoreRhosts yes
LogLevel VERBOSE
Banner /etc/issue.net
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256
EOF
chmod 600 /etc/ssh/sshd_config.d/10-hvmc-hardening.conf
sshd -t                                   # abort before restart if the config is invalid
systemctl restart ssh

cat > /etc/fail2ban/jail.d/hvmc-sshd.local <<'EOF'
[sshd]
enabled  = true
backend  = systemd
port     = ssh
maxretry = 3
findtime = 10m
bantime  = 1h
EOF
systemctl enable fail2ban >/dev/null
systemctl restart fail2ban

# ---------------------------------------------------------------- 4. sysctl baseline
echo "== [4] kernel / network hardening"
cat > /etc/sysctl.d/60-hvmc-hardening.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
EOF
sysctl --system >/dev/null

echo "== hardening complete on $(hostname) at $(date -u +%FT%TZ)"
