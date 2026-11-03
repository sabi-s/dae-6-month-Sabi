#!/usr/bin/env bash
# DC STEP 5 - analyse the four captures with tshark and write ~/symdc_evidence/analysis/summary.txt
STEP=05_analyze
source "$(dirname "$0")/common.sh"
run "capture analysis" python3 "$KIT/tools/analyze.py" "$EVID"
B=$(python3 - "$EVID/pcaps" <<'PY'
import os, sys
d = sys.argv[1]
c = lambda n: open(os.path.join(d, n), "rb").read().count(b"HVMC-DEMO-NOTE") if os.path.exists(os.path.join(d, n)) else -1
print(c("smb_before.pcap"), c("smb_after.pcap"))
PY
)
read -r BEFORE AFTER <<< "$B"
if [[ "$BEFORE" -gt 0 && "$AFTER" == 0 ]]; then ok "The fictional note is readable in smb_before ($BEFORE times) and gone in smb_after (0)"
else fail "Unexpected marker counts: before=$BEFORE after=$AFTER (-1 = capture missing)"; fi
grep -q "KDC_ERR_ETYPE_NOSUPP" "$EVID/analysis/summary.txt" && ok "krb_after shows the KDC refusing RC4 (KDC_ERR_ETYPE_NOSUPP)" \
  || fail "No RC4 refusal found in krb_after - check that 01_kerberos_aes.sh apply ran before the capture"
shot "the summary"
