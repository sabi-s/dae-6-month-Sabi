#!/usr/bin/env bash
# DC STEP 0 - check the domain controller is ready, install the capture tools, and save the starting state.
# Changes nothing on the DC except installing tcpdump and tshark if they are missing.
STEP=00_precheck
source "$(dirname "$0")/common.sh"
need_sudo
say "Server"
run "host name and lab address" bash -c "hostname -f; ip -4 -br a show $LAB_IF"
run "Samba version (4.17 or later is needed for the Kerberos setting)" samba --version
run "domain controller service" systemctl is-active samba-ad-dc || { fail "samba-ad-dc is not running - start it: sudo systemctl start samba-ad-dc"; exit 1; }

say "Department shares from Week 5"
run "shares under /srv/shares" sudo python3 "$EDIT" list-shares /srv/shares
sudo python3 "$EDIT" list-shares /srv/shares | grep -qx EHR || { fail "No [EHR] share found - the Week 5 EHR share is needed"; exit 1; }

say "Domain users and groups seen by Linux (Week 5 libnss-winbind)"
for u in sarah.chen brian.adeyemi; do run "user $u" id "HVMC\\$u"; done
for g in sg-doctors-ehr-rw sg-finance-payroll-rw; do run "group $g" getent group "HVMC\\$g"; done

say "Tools"
command -v python3 >/dev/null && run "python" python3 --version
[[ -f "$SYM/aes.py" && -f "$SYM/key_management.py" ]] && ok "Found your AES code from the Symmetric Cryptography rubric ($SYM)" \
  || { fail "symmetric_crypto folder missing - re-run the git sparse-checkout command in the guide"; exit 1; }
if ! command -v tshark >/dev/null || ! command -v tcpdump >/dev/null; then
  run "refresh the package list" sudo apt-get update
  run "install tcpdump and tshark" sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump tshark acl
fi
command -v setfacl >/dev/null || run "install ACL tools" sudo apt-get install -y acl
run "tool versions" bash -c "tcpdump --version 2>&1 | head -1; tshark --version | head -1; setfacl --version"

say "Starting state (saved for the report)"
sudo testparm -s 2>/dev/null > "$EVID/configs/smb.conf-before.txt"
run "Kerberos and SMB encryption settings today" bash -c "sudo testparm -s --parameter-name='kdc supported enctypes' 2>/dev/null; sudo testparm -s --section-name=EHR --parameter-name='server smb encrypt' 2>/dev/null"
ok "Precheck passed: $(hostname -f), Samba running, EHR share present"
shot "this window"
