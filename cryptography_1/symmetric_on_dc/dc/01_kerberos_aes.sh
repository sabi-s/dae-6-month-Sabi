#!/usr/bin/env bash
# DC STEP 1 - Kerberos tickets with AES only (RC4 switched off).
#   ./01_kerberos_aes.sh show    read-only: what the KDC allows today
#   ./01_kerberos_aes.sh apply   allow only AES-256 and AES-128 (kdc supported enctypes = 24), restart Samba, verify
#   ./01_kerberos_aes.sh undo    remove the setting again (back to Samba's default)
# 24 = 8 (aes128-cts-hmac-sha1-96) + 16 (aes256-cts-hmac-sha1-96). RC4 (arcfour-hmac, 4) is left out.
# Windows equivalent: GPO "Network security: Configure encryption types allowed for Kerberos".
STEP=01_kerberos_aes
source "$(dirname "$0")/common.sh"
MODE="${1:-show}"
need_sudo

show() {
  say "Kerberos encryption types allowed by the domain controller's KDC"
  run "kdc supported enctypes (0 = Samba default: RC4 and AES both allowed)" sudo testparm -s --parameter-name="kdc supported enctypes"
  run "the client computer account's msDS-SupportedEncryptionTypes" bash -c \
    "sudo samba-tool computer show HVMC-CLIENT01 --attributes=msDS-SupportedEncryptionTypes 2>&1 | grep -iv '^dn:' || true"
  echo "(msDS-SupportedEncryptionTypes: 24 = AES only, 28 = RC4 + AES, empty = domain default.)"
  sudo testparm -s --parameter-name="kdc supported enctypes" > "$EVID/configs/kdc-enctypes-$1.txt" 2>/dev/null
}

case "$MODE" in
  show) show now; shot "the kdc supported enctypes value and the computer account" ;;
  apply)
    show before
    say "Allow only AES in the KDC"
    B=$(backup_conf kerberos); echo "backup: $B"
    run "add 'kdc supported enctypes = 24' to [global]" sudo python3 "$EDIT" set-global "kdc supported enctypes" 24 \
      || { fail "smb.conf was not changed"; exit 1; }
    conf_ok || { fail "testparm rejected the change - restoring"; sudo cp -p "$B" "$CONF"; cat "$EVID/logs/testparm-$STEP.txt"; exit 1; }
    run "restart the domain controller service (the KDC reads this at start)" sudo systemctl restart samba-ad-dc
    sleep 6
    if ! systemctl is-active --quiet samba-ad-dc; then
      fail "Samba did not start - restoring the backup"; sudo cp -p "$B" "$CONF"; sudo systemctl restart samba-ad-dc; exit 1
    fi
    show after
    sudo testparm -s 2>/dev/null > "$EVID/configs/smb.conf-after-kerberos.txt"
    ok "KDC now allows AES only (kdc supported enctypes = 24). Next: capture krb_after with the client test."
    shot "the setting before and after" ;;
  undo)
    B=$(backup_conf kerberos-undo); echo "backup: $B"
    run "remove the setting" sudo python3 "$EDIT" undo "kdc supported enctypes"
    run "restart" sudo systemctl restart samba-ad-dc; sleep 6
    systemctl is-active --quiet samba-ad-dc && ok "Back to the Samba default (RC4 allowed again)" || fail "Samba did not start - restore $B" ;;
  *) echo "usage: $0 show|apply|undo"; exit 1 ;;
esac
