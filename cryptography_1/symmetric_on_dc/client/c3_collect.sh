#!/usr/bin/env bash
# CLIENT STEP 3 - pack the client evidence into ~/symdc_evidence_client.tar.gz (logs only; no passwords or tickets).
STEP=c3_collect
source "$(dirname "$0")/common.sh"
cp /etc/krb5.conf "$EVID/logs/krb5.conf-client.txt" 2>/dev/null
kdestroy -A 2>/dev/null
rm -f "$HOME/symdc_evidence_client.tar.gz"
tar -czf "$HOME/symdc_evidence_client.tar.gz" -C "$HOME" symdc_evidence
run "evidence package" ls -l "$HOME/symdc_evidence_client.tar.gz"
ok "Packed ~/symdc_evidence_client.tar.gz (your Kerberos tickets were cleared)"
