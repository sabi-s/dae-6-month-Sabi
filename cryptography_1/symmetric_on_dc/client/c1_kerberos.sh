#!/usr/bin/env bash
# CLIENT STEP 1 - Kerberos sign-in test, run while the DC captures (./03_capture.sh krb_before or krb_after).
#   ./c1_kerberos.sh before    expected: normal sign-in uses AES-256, and an RC4-only sign-in is ACCEPTED (the weakness)
#   ./c1_kerberos.sh after     expected: normal sign-in still uses AES-256, and the RC4-only sign-in is REFUSED
STEP=c1_kerberos
MODE="${1:-}"
[[ "$MODE" == before || "$MODE" == after ]] || { echo "usage: $0 before|after"; exit 1; }
STEP="c1_kerberos_$MODE"
source "$(dirname "$0")/common.sh"
TMPD=$(mktemp -d); trap 'rm -rf "$TMPD"' EXIT

say "1. Normal sign-in as sarah.chen ($MODE)"
kdestroy -A 2>/dev/null
sign_in sarah.chen || { fail "Sign-in failed - check the password and try again"; exit 1; }
run "ticket-granting ticket and its encryption types" klist -e
run "ticket for the file server (used in the SMB part)" bash -c "kvno cifs/$DC_NAME@$REALM && klist -e | tail -4"
klist -e | grep -A2 "krbtgt/" | grep "Etype" | grep -q "aes256" && ok "Normal sign-in uses AES-256" || fail "The ticket is not AES-256"

say "2. A sign-in that offers ONLY RC4 (like an old or downgraded client)"
cat > "$TMPD/krb5.conf" <<CONF
[libdefaults]
  default_realm = $REALM
  dns_lookup_kdc = false
  allow_weak_crypto = true
  allow_rc4 = true
  default_tkt_enctypes = rc4-hmac
  default_tgs_enctypes = rc4-hmac
  permitted_enctypes = rc4-hmac
[realms]
  $REALM = {
    kdc = $DC_NAME
  }
CONF
printf '\n### RC4-only client settings\n' >> "$EVID/logs/$STEP.txt"; cat "$TMPD/krb5.conf" >> "$EVID/logs/$STEP.txt"
echo "${BOLD}If asked, type sarah.chen's password again.${RESET}"
KRB5_CONFIG="$TMPD/krb5.conf" KRB5CCNAME="FILE:$TMPD/rc4cc" kinit "sarah.chen@$REALM" 2> >(tee "$TMPD/err" >&2)
RC=$?
sleep 1
{ printf '\n### RC4-only sign-in: exit %s\n' "$RC"; cat "$TMPD/err"; } >> "$EVID/logs/$STEP.txt"
if [[ "$RC" == 0 ]]; then
  run "the RC4 ticket" env KRB5_CONFIG="$TMPD/krb5.conf" klist -e -c "FILE:$TMPD/rc4cc"
  [[ "$MODE" == before ]] && ok "As expected BEFORE the change: the domain controller still hands out RC4 tickets (weak)" \
                          || fail "RC4 was still accepted AFTER the change - check 01_kerberos_aes.sh apply on the DC"
else
  if grep -qi "encryption type" "$TMPD/err"; then
    [[ "$MODE" == after ]] && ok "RC4 refused by the domain controller: $(tr -d '\n' < "$TMPD/err")" \
                           || fail "RC4 was refused already before the change: $(tr -d '\n' < "$TMPD/err")"
  else
    fail "The RC4 sign-in failed for another reason (wrong password?): $(tr -d '\n' < "$TMPD/err")"
  fi
fi
echo; echo "${BOLD}Done.${RESET} Go back to the DC window and press Enter."
shot "this window"
