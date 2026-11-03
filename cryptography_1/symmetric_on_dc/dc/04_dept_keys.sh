#!/usr/bin/env bash
# DC STEP 4 - one AES-256 key per department, enforced by Active Directory group membership.
# Installs dept_vault.py (built on your from-scratch AES code) to /opt/hvmc-vault, creates keys for Doctors and
# Finance, encrypts one fictional record for each, and tests who can decrypt what - as the real domain users.
STEP=04_dept_keys
source "$(dirname "$0")/common.sh"
need_sudo
BIN=/opt/hvmc-vault
V=/srv/hvmc-vault
PASSED=0; FAILED=0

vault_as() {                   # vault_as <user> <group> <args...>  - run the vault tool as that domain user
  local u="$1" g="$2"; shift 2
  if getent passwd "HVMC\\$u" >/dev/null; then
    (cd / && sudo -u "HVMC\\$u" env PYTHONDONTWRITEBYTECODE=1 python3 "$BIN/dept_vault.py" "$@")
  else                         # fallback: a throw-away identity holding only that group
    (cd / && sudo -u nobody -g "HVMC\\$g" env PYTHONDONTWRITEBYTECODE=1 python3 "$BIN/dept_vault.py" "$@")
  fi
}
expect() {                     # expect <exit-code> "<title>" command...
  local want="$1" title="$2"; shift 2
  run "$title" "$@"; local got=$?
  if [[ "$got" == "$want" ]]; then ok "$title (exit $got as expected)"; PASSED=$((PASSED+1))
  else fail "$title (exit $got, expected $want)"; FAILED=$((FAILED+1)); fi
}

say "Install the vault tool with your AES code"
run "copy to $BIN (root-owned, read-only for users)" bash -c "sudo install -d -m 755 $BIN && \
  sudo install -m 644 '$SYM/aes.py' '$SYM/key_management.py' '$KIT/tools/dept_vault.py' $BIN/ && ls -l $BIN"
getent passwd 'HVMC\sarah.chen' >/dev/null && echo "Tests run as the real domain users sarah.chen (Doctors) and brian.adeyemi (Finance)." \
  || echo "Domain users are not visible to sudo here - tests use a temporary identity holding only the department group."

say "Create one key per department"
run "vault folders" sudo install -d -m 755 $V $V/keys $V/records
expect 0 "Doctors key (readable only by HVMC\\sg-doctors-ehr-rw)" sudo python3 $BIN/dept_vault.py init doctors
expect 0 "Finance key (readable only by HVMC\\sg-finance-payroll-rw)" sudo python3 $BIN/dept_vault.py init finance
run "who can read the keys" bash -c "sudo ls -l $V/keys/*; sudo getfacl -p $V/keys/doctors $V/keys/finance 2>/dev/null"
shot "the key folders and their ACLs"

say "Encrypt one fictional record per department"
expect 0 "encrypt the Doctors note" sudo python3 $BIN/dept_vault.py encrypt doctors "$KIT/tools/samples/doctors_note.txt" note-0001
expect 0 "encrypt the Finance note" sudo python3 $BIN/dept_vault.py encrypt finance "$KIT/tools/samples/finance_note.txt" batch-0001
run "the stored record is ciphertext (anyone can read the file)" cat $V/records/doctors/note-0001.json
N=$(grep -c "HVMC-DEMO-NOTE" $V/records/doctors/note-0001.json)
[[ "$N" == 0 ]] && { ok "The patient text does not appear in the stored record"; PASSED=$((PASSED+1)); } \
                || { fail "Plain text found in the stored record"; FAILED=$((FAILED+1)); }

say "Who can decrypt? (role-based access to the key)"
expect 0 "T1 sarah.chen (Doctors) opens the Doctors record"     vault_as sarah.chen sg-doctors-ehr-rw decrypt doctors note-0001
expect 3 "T2 brian.adeyemi (Finance) is refused the Doctors key" vault_as brian.adeyemi sg-finance-payroll-rw decrypt doctors note-0001
expect 0 "T3 brian.adeyemi (Finance) opens the Finance record"  vault_as brian.adeyemi sg-finance-payroll-rw decrypt finance batch-0001
expect 3 "T4 sarah.chen (Doctors) is refused the Finance key"   vault_as sarah.chen sg-doctors-ehr-rw decrypt finance batch-0001
expect 0 "T5 a changed record is detected (HMAC check before decrypting)" vault_as sarah.chen sg-doctors-ehr-rw tamper-test doctors note-0001
shot "T1 to T5"

say "Key rotation"
run "Doctors key before" sudo ls $V/keys/doctors
expect 0 "T6 rotate the Doctors key (new key, re-wrap every record, destroy the old key)" sudo python3 $BIN/dept_vault.py rotate doctors
run "Doctors key after" bash -c "sudo ls $V/keys/doctors; grep kek_version $V/records/doctors/note-0001.json"
expect 0 "T7 sarah.chen still opens the record with the new key" vault_as sarah.chen sg-doctors-ehr-rw decrypt doctors note-0001
shot "the rotation and T7"

echo
echo "Results: $PASSED passed, $FAILED failed" | tee -a "$EVID/logs/$STEP.txt"
[[ "$FAILED" == 0 ]] && ok "Department keys work: only each department's group can decrypt its records" \
                     || fail "Some tests failed - the log is in ~/symdc_evidence/logs/$STEP.txt"
