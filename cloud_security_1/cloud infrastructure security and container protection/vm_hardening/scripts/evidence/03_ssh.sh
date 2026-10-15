#!/bin/bash
# Evidence 3 - effective SSH configuration
echo "### sshd -T (effective settings)"
sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|permitemptypasswords|pubkeyauthentication|authenticationmethods|allowusers|maxauthtries|logingracetime|clientaliveinterval|clientalivecountmax|x11forwarding|allowtcpforwarding|allowagentforwarding|banner|loglevel) '
echo; echo "### ciphers / macs / kex"; sshd -T | grep -E '^(ciphers|macs|kexalgorithms) ' | cut -c1-160
echo; echo "### authorized key type for hvmcadmin"; awk '{print $1, $3}' /home/hvmcadmin/.ssh/authorized_keys
echo; echo "### hvmcadmin password state (L/NP = no usable password)"; passwd -S hvmcadmin
