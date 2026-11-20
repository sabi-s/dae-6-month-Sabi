#!/usr/bin/env bash
# Step 3 - Protect the audit trail (equivalent of the AWS "Deny-Disable-Logging" SCP).
# CanNotDelete locks: the Log Analytics workspace (Sentinel) and the security-log storage account
# cannot be deleted - even by an Owner - until the lock is removed (and removing a lock is itself logged).
export MSYS_NO_PATHCONV=1
OUT=evidence/03_protect_logging.txt
{
  echo "== Step 3 run: $(date -u +%Y-%m-%dT%H:%MZ)"
  az lock create -n HVMC-Protect-SecOps-LAW --lock-type CanNotDelete -g HVMC-CloudSecurity-RG \
     --resource HVMC-SecOps-LAW --resource-type Microsoft.OperationalInsights/workspaces \
     --notes "HIPAA 164.312(b) audit controls - do not delete the Sentinel workspace" --query "{name:name,level:level}" -o json
  az lock create -n HVMC-Protect-SecurityLogs --lock-type CanNotDelete -g HVMC-CloudSecurity-RG \
     --resource hvmcseclogsc36407 --resource-type Microsoft.Storage/storageAccounts \
     --notes "HIPAA 164.312(b) audit controls - security log archive" --query "{name:name,level:level}" -o json
  echo; echo "== Locks after Step 3"
  az lock list --query "[].{Name:name,Level:level,Notes:notes}" -o table
} 2>&1 | tr -d '\r' | bash mask.sh > "$OUT"
cat "$OUT"
