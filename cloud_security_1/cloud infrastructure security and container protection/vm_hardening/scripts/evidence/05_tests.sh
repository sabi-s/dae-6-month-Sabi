#!/bin/bash
# Evidence 5 - negative tests (these attempts are EXPECTED to fail)
ssh_try() { timeout 15 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 "$@" 2>&1 | grep -vE 'Warning: Permanently|^\*|^ [A-Za-z(]' | tail -2; }
echo "### T1 password login for hvmcadmin (expect: Permission denied (publickey))"
ssh_try -o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no hvmcadmin@127.0.0.1 true
echo; echo "### T2 root login (expect: Permission denied)"
ssh_try -o PreferredAuthentications=password -o PubkeyAuthentication=no root@127.0.0.1 true
echo; echo "### T3 weak cipher aes128-cbc (expect: no matching cipher)"
ssh_try -c aes128-cbc hvmcadmin@127.0.0.1 true
echo; echo "### T4 weak MAC hmac-sha1 (expect: no matching MAC)"
ssh_try -m hmac-sha1 hvmcadmin@127.0.0.1 true
echo; echo "### T5 sshd log of the refused attempts"
journalctl -u ssh --since "-5 min" --no-pager -o cat | grep -Ei 'not allowed|invalid|no matching|Connection closed by authenticating|disconnect' | tail -5
echo; echo "### T6 recent UFW blocks (inbound traffic dropped by host firewall)"
journalctl -k --since "-24 h" --no-pager -o short | grep 'UFW BLOCK' | tail -4 | cut -c1-200 || echo "(none logged yet)"
