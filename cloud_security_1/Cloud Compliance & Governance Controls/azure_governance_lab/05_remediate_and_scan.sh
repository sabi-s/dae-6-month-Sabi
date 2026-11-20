#!/usr/bin/env bash
# Step 5 - Fix existing resources (remediation tasks for the Modify/inherit-tag rules) and run a compliance scan.
export MSYS_NO_PATHCONV=1
SUB=$(az account show --query id -o tsv | tr -d '\r')
OUT=evidence/05_remediate_and_scan.txt
{
  echo "== Step 5 run: $(date -u +%Y-%m-%dT%H:%MZ)"
  echo "-- Starting compliance scan (subscription)"; az policy state trigger-scan --no-wait
  for RG in HVMC-CloudSecurity-RG HVMC-KeyVault-RG; do
    for T in Owner Environment DataClassification CostCenter; do
      az policy remediation create -n "hvmc-inherit-${T,,}-${RG,,}" -g "$RG" \
         --policy-assignment "/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Authorization/policyAssignments/hvmc-tags-${RG,,}" \
         --definition-reference-id "Inherit-$T" --resource-discovery-mode ReEvaluateCompliance \
         --query "{task:name,state:provisioningState}" -o json
    done
  done
} 2>&1 | tr -d '\r' | bash mask.sh > "$OUT"
cat "$OUT"
