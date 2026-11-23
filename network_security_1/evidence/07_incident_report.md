# Incident Report — SSH brute-force attempt against hvmc-dc01

**Lab:** AccessGuard Health — Horizon Valley Medical Center (HVMC)
**Host:** hvmc-dc01 (192.168.56.10), Ubuntu + Samba 4.19 AD DC, lab subnet 192.168.56.0/24
**Date:** Mon Nov 23 12:38:48 AM UTC 2026
**Classification:** Authentication attack (SSH brute force) — detected and blocked. Controlled lab self-test.

## Detect
- SSH authentication failures recorded for a non-existent account (see `ssh_auth_failures.txt`).
- fail2ban sshd jail reached its retry threshold and raised a ban (see `fail2ban_log.txt`,
  `fail2ban_status.txt`). Banned IP list at collection time: **192.168.56.11**.

## Contain
- fail2ban inserted a firewall block for the source (see `fail2ban_iptables_rules.txt`).
- UFW already restricts inbound SSH to the lab subnet only (see `ufw_status.txt`).

## Eradicate
- No account was compromised: the targeted username does not exist on the DC and no successful
  authentication appears in the logs. Confirm by searching the same window for an "Accepted" line.

## Recover
- The temporary ban expires after the configured bantime; to clear it immediately:
  `sudo fail2ban-client set sshd unbanip <IP>`.

## Lessons learned / hardening
- Keep SSH password auth disabled on the DC where possible; prefer key-based login.
- Alert prioritisation: repeated failures against the domain controller are HIGH priority.
- Consider lowering maxretry and raising bantime for internet-facing hosts (not needed on this
  host-only lab, which has no inbound route from outside).

## Evidence files
- authlog_failures.txt
- fail2ban_iptables_rules.txt
- fail2ban_log.txt
- fail2ban_status.txt
- incident_report.md
- manifest.txt
- ssh_auth_failures.txt
- ufw_status.txt
