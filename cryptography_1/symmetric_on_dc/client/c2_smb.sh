#!/usr/bin/env bash
# CLIENT STEP 2 - file-share test on the Week 5 EHR share, run while the DC captures (./03_capture.sh smb_before|smb_after).
#   ./c2_smb.sh before   Sarah writes and reads a FICTIONAL note (readable on the network: not encrypted yet)
#   ./c2_smb.sh after    the same, now encrypted; plus: an old SMB 2.1 client is refused, and Finance is still refused
STEP=c2_smb
MODE="${1:-}"
[[ "$MODE" == before || "$MODE" == after ]] || { echo "usage: $0 before|after"; exit 1; }
STEP="c2_smb_$MODE"
source "$(dirname "$0")/common.sh"
TMPD=$(mktemp -d); trap 'rm -rf "$TMPD"' EXIT
NOTE="$TMPD/symdc_demo_note.txt"
printf '%s | EHR | FICTIONAL demo note, no real patient | Jane Testcase MRN DEMO-4471 | %s\n' "$MARKER" "$(date -u +%FT%TZ)" > "$NOTE"

klist -s 2>/dev/null || sign_in sarah.chen || { fail "Sign-in failed"; exit 1; }
run "signed in as" bash -c "klist | head -2"

say "Sarah (Doctors) writes and reads the note in the EHR share ($MODE)"
echo "(The connection stays open for a few seconds so the DC can record how it is protected.)"
{ echo "put $NOTE symdc_demo_note.txt"; echo "get symdc_demo_note.txt $TMPD/back.txt"; echo "ls symdc*"; sleep 12; echo "exit"; } \
  | smbclient "$SHARE" --use-kerberos=required 2>&1 | tee -a "$EVID/logs/$STEP.txt"
cmp -s "$NOTE" "$TMPD/back.txt" && ok "Sarah can still write and read in EHR" || fail "The note did not come back the same"

if [[ "$MODE" == after ]]; then
  say "An old client that cannot encrypt (SMB 2.1) is refused"
  run "SMB 2.1 connection" smbclient "$SHARE" --use-kerberos=required -m SMB2_10 -c ls
  [[ $? != 0 ]] && ok "SMB 2.1 (no encryption) is refused by the EHR share" || fail "SMB 2.1 was allowed in"

  say "Permissions are unchanged: Finance (brian.adeyemi) is still refused on EHR"
  BCC="FILE:$TMPD/brian_cc"
  if sign_in brian.adeyemi "$BCC"; then
    KRB5CCNAME="$BCC" run "brian.adeyemi opens EHR" smbclient "$SHARE" --use-kerberos=required -c ls > "$TMPD/brian.txt"
    cat "$TMPD/brian.txt"
    grep -q "NT_STATUS_ACCESS_DENIED" "$TMPD/brian.txt" && ok "Brian (Finance) refused: NT_STATUS_ACCESS_DENIED" \
      || fail "Brian was not refused as expected"
    KRB5CCNAME="$BCC" kdestroy 2>/dev/null
  else
    fail "Brian's sign-in failed - skip this test or try again"
  fi
  smbclient "$SHARE" --use-kerberos=required -c "del symdc_demo_note.txt" >/dev/null 2>&1 && echo "(demo note removed from EHR)"
fi
echo; echo "${BOLD}Done.${RESET} Go back to the DC window and press Enter."
shot "this window"
