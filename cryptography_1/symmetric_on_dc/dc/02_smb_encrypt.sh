#!/usr/bin/env bash
# DC STEP 2 - SMB3 encryption (AES) on the Week 5 department shares.
#   ./02_smb_encrypt.sh show    read-only: current setting per share
#   ./02_smb_encrypt.sh apply   'server smb encrypt = required' on every share under /srv/shares, reload Samba
#   ./02_smb_encrypt.sh undo    remove it again
# sysvol and netlogon are not touched. Permissions (valid users, ACLs) are not changed - only the traffic is encrypted.
STEP=02_smb_encrypt
source "$(dirname "$0")/common.sh"
MODE="${1:-show}"
need_sudo

show() {
  say "SMB encryption per department share ($1)"
  for s in $(sudo python3 "$EDIT" list-shares /srv/shares); do
    printf '  %-16s server smb encrypt = %s\n' "[$s]" "$(sudo testparm -s --section-name="$s" --parameter-name='server smb encrypt' 2>/dev/null)"
  done | tee -a "$EVID/logs/$STEP.txt" | tee "$EVID/configs/smb-encrypt-$1.txt"
  echo "(default = encrypt only if the client asks; required = every connection must be encrypted, or it is refused.)"
}

case "$MODE" in
  show) show now; shot "the setting for each share" ;;
  apply)
    show before
    B=$(backup_conf smb); echo "backup: $B"
    run "require encryption on the department shares" sudo python3 "$EDIT" set-shares "server smb encrypt" required /srv/shares \
      || { fail "smb.conf was not changed"; exit 1; }
    conf_ok || { fail "testparm rejected the change - restoring"; sudo cp -p "$B" "$CONF"; cat "$EVID/logs/testparm-$STEP.txt"; exit 1; }
    run "tell the running file service to re-read smb.conf (no restart needed)" sudo smbcontrol all reload-config
    show after
    sudo testparm -s 2>/dev/null > "$EVID/configs/smb.conf-after-smb.txt"
    ok "SMB3 encryption is now required on the department shares. Next: capture smb_after with the client test."
    shot "the setting before and after" ;;
  undo)
    B=$(backup_conf smb-undo); echo "backup: $B"
    run "remove the setting" sudo python3 "$EDIT" undo "server smb encrypt"
    conf_ok && sudo smbcontrol all reload-config && ok "Encryption back to the default" || fail "Check smb.conf - backup at $B" ;;
  *) echo "usage: $0 show|apply|undo"; exit 1 ;;
esac
