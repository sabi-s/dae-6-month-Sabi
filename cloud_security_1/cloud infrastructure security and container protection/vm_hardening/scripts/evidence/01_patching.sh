#!/bin/bash
# Evidence 1 - automated patching
echo "### OS"; lsb_release -ds; uname -r
echo; echo "### /etc/apt/apt.conf.d/20auto-upgrades"; cat /etc/apt/apt.conf.d/20auto-upgrades
echo; echo "### HVMC unattended-upgrades policy"; grep -v '^//' /etc/apt/apt.conf.d/52hvmc-unattended-upgrades
echo; echo "### systemd timers"; systemctl list-timers apt-daily.timer apt-daily-upgrade.timer --no-pager | head -4
echo; echo "### unattended-upgrades service"; systemctl is-enabled unattended-upgrades; systemctl is-active unattended-upgrades
echo; echo "### dry run"; unattended-upgrade --dry-run --verbose 2>&1 | grep -E "Allowed origins|Packages that will be upgraded|No packages found|Initial blacklist" | head -6
echo; echo "### pending security updates"; apt list --upgradable 2>/dev/null | grep -c -- -security || true
