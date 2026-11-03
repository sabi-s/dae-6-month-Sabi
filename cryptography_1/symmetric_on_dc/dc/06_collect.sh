#!/usr/bin/env bash
# DC STEP 6 - pack the evidence for the report into ~/symdc_evidence_dc.tar.gz (no passwords, no keys).
STEP=06_collect
source "$(dirname "$0")/common.sh"
need_sudo
sudo testparm -s 2>/dev/null > "$EVID/configs/smb.conf-final.txt"
ls -1 /etc/samba/smb.conf.before-symdc-* > "$EVID/configs/backups.txt" 2>/dev/null
sudo ls -lR /srv/hvmc-vault > "$EVID/configs/vault-listing.txt" 2>&1       # names and permissions only, not key contents
rm -f "$HOME/symdc_evidence_dc.tar.gz"
tar -czf "$HOME/symdc_evidence_dc.tar.gz" -C "$HOME" symdc_evidence
if tar -tzf "$HOME/symdc_evidence_dc.tar.gz" | grep -q '\.key$'; then fail "A key file got into the evidence - do not send it"; exit 1; fi
run "evidence package" ls -l "$HOME/symdc_evidence_dc.tar.gz"
ok "Packed ~/symdc_evidence_dc.tar.gz"
