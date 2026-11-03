#!/usr/bin/env bash
# CLIENT STEP 0 - check hvmc-client01 is joined to HVMC.LAN and has the Kerberos and SMB tools. Read-only.
STEP=c0_precheck
source "$(dirname "$0")/common.sh"
run "host name and lab address" bash -c "hostname; ip -4 -br a show enp0s8"
run "domain membership (Week 2)" realm list
run "the domain controller is found" host -t A "$DC_NAME"
run "Sarah is a domain user here" id "sarah.chen@hvmc.lan"
if ! command -v smbclient >/dev/null; then run "install smbclient" sudo apt-get install -y smbclient; fi
run "tools" bash -c "command -v kinit klist kvno smbclient; smbclient --version"
echo "The next command shows the encryption types of this computer's own Kerberos keys (names only, no key values)."
run "computer keytab encryption types" bash -c "sudo klist -ke /etc/krb5.keytab | awk 'NR>3 {print \$1, \$2, \$NF}' | sort -u"
realm list | grep -q "configured: kerberos-member" && ok "Precheck passed: $(hostname) is a member of HVMC.LAN" \
  || fail "This client does not look joined to HVMC.LAN - see the Week 2 document"
shot "this window"
