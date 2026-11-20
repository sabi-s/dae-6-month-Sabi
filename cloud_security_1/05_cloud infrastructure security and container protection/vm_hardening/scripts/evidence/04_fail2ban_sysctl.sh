#!/bin/bash
# Evidence 4 - brute-force protection and kernel baseline
echo "### fail2ban"; fail2ban-client status; echo; fail2ban-client status sshd
echo; echo "### jail settings"; cat /etc/fail2ban/jail.d/hvmc-sshd.local
echo; echo "### sysctl"; sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_redirects net.ipv4.tcp_syncookies kernel.randomize_va_space kernel.kptr_restrict fs.suid_dumpable
