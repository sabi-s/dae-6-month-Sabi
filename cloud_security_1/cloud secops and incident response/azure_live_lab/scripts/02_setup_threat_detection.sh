#!/bin/bash
# HVMC Cloud Security Operations & Incident Response - Step 2
# Threat detection (AWS GuardDuty equivalent): Microsoft Defender for Cloud + Microsoft Sentinel
# Horizon Valley Medical Center | Author: Sabitha S Karanavar
#
#   GuardDuty (threat detection)  -> Defender for Storage (activity anomalies + on-upload malware scanning)
#                                    Defender for Resource Manager (suspicious management operations)
#   Security Hub / SIEM           -> Microsoft Sentinel on HVMC-SecOps-LAW
#                                    4 custom KQL analytics rules + Defender alerts -> incidents
#   Finding notifications         -> Defender security contact e-mail (Medium and above)
#
# COST (free-trial credit, spending limit ON - no card charge), expected $0 - $0.15:
#   Defender for Storage + Resource Manager: 30-day free trial (confirmed available on this subscription)
#   Malware scanning is billed outside the trial at $0.15/GB scanned; capped here at 1 GB/month/account
#   Sentinel: 31-day free trial on this new workspace (10 GB/day free)
#   AFTER the trials (only if you upgrade to Pay-As-You-Go): ~$10/storage account/month + Sentinel ingestion
#   -> 99_teardown.sh returns both plans to Free and removes Sentinel.
set -euo pipefail
export PATH="$HOME/.azure-cli-env/bin:$PATH" PYTHONWARNINGS=ignore AZURE_CORE_ONLY_SHOW_ERRORS=true
HERE="$(cd "$(dirname "$0")" && pwd)"; EVID="$HERE/../evidence"; mkdir -p "$EVID"

ALERT_EMAIL="sabithaskaranavar@gmail.com"
SUB=$(az account show --query id -o tsv)
RG=HVMC-CloudSecurity-RG
LAW_ID=$(az monitor log-analytics workspace show -g $RG -n HVMC-SecOps-LAW --query id -o tsv)
ARM=https://management.azure.com
SI="$ARM$LAW_ID/providers/Microsoft.SecurityInsights"
SIV="api-version=2024-03-01"

step() { echo; echo "=== $*"; }
guid() { python3 -c "import uuid,sys; print(uuid.uuid5(uuid.NAMESPACE_URL, sys.argv[1]))" "$1"; }   # stable id = re-runnable

step "1/6 register providers (free)"
for p in Microsoft.SecurityInsights Microsoft.EventGrid; do
  az provider register --namespace $p --wait -o none; echo "  $p registered"
done

step "2/6 Defender for Storage (activity monitoring + malware scanning, 1 GB/month cap)"
az rest --method put -o none --url "$ARM/subscriptions/$SUB/providers/Microsoft.Security/pricings/StorageAccounts?api-version=2024-01-01" \
  --body '{"properties":{"pricingTier":"Standard","subPlan":"DefenderForStorageV2","extensions":[
            {"name":"OnUploadMalwareScanning","isEnabled":"True","additionalExtensionProperties":{"CapGBPerMonthPerStorageAccount":"1"}},
            {"name":"SensitiveDataDiscovery","isEnabled":"False"}]}}'
echo "  StorageAccounts plan -> Standard (covers hvmcehrstorage and the log account)"

step "3/6 Defender for Resource Manager (suspicious control-plane operations)"
az rest --method put -o none --url "$ARM/subscriptions/$SUB/providers/Microsoft.Security/pricings/Arm?api-version=2024-01-01" \
  --body '{"properties":{"pricingTier":"Standard"}}'
echo "  Arm plan -> Standard"

step "4/6 Defender security contact (e-mail on alerts of Medium severity and above)"
az rest --method put -o none --url "$ARM/subscriptions/$SUB/providers/Microsoft.Security/securityContacts/default?api-version=2023-12-01-preview" \
  --body "{\"properties\":{\"emails\":\"$ALERT_EMAIL\",\"isEnabled\":true,
           \"notificationsByRole\":{\"state\":\"On\",\"roles\":[\"Owner\"]},
           \"notificationsSources\":[{\"sourceType\":\"Alert\",\"minimalSeverity\":\"Medium\"}]}}"
echo "  security contact -> $ALERT_EMAIL"

step "5/6 Microsoft Sentinel on HVMC-SecOps-LAW + Defender for Cloud connector"
az rest --method put -o none --url "$SI/onboardingStates/default?$SIV" --body '{"properties":{}}'
echo "  Sentinel enabled (31-day free trial)"
if az rest --method put -o none --url "$SI/dataConnectors/$(guid hvmc-mdc-connector)?$SIV" \
     --body "{\"kind\":\"AzureSecurityCenter\",\"properties\":{\"subscriptionId\":\"$SUB\",\"dataTypes\":{\"alerts\":{\"state\":\"Enabled\"}}}}" 2>"$EVID/.connector_err.txt"; then
  echo "  Defender for Cloud alerts connector -> Sentinel"
else
  echo "  NOTE: connector not created ($(tail -1 "$EVID/.connector_err.txt" | cut -c1-140)) - continuing"
fi

step "6/6 Sentinel analytics rules (KQL detections -> incidents)"
FAILED=0
for f in "$HERE"/sentinel_rules/*.json; do
  name=$(basename "$f" .json)
  if az rest --method put -o none --url "$SI/alertRules/$(guid "hvmc-$name")?$SIV" --body @"$f" 2>"$EVID/.rule_err.txt"; then
    echo "  created  $name"
  else
    echo "  FAILED   $name: $(grep -o '"message":"[^"]*' "$EVID/.rule_err.txt" | head -1 | cut -c12-200)"; FAILED=$((FAILED+1))
  fi
done
rm -f "$EVID/.rule_err.txt"

step "evidence"
{
  echo "### Defender for Cloud plans"
  az security pricing list -o table --query "value[?contains(['StorageAccounts','Arm','CloudPosture','FoundationalCspm'],name)].{Plan:name,Tier:pricingTier,SubPlan:subPlan,FreeTrialLeft:freeTrialRemainingTime}"
  echo; echo "### Defender for Storage extensions"
  az rest --method get --url "$ARM/subscriptions/$SUB/providers/Microsoft.Security/pricings/StorageAccounts?api-version=2024-01-01" \
    --query "properties.extensions[].{name:name,enabled:isEnabled,settings:additionalExtensionProperties}" -o json
  echo; echo "### Security contact"
  az rest --method get --url "$ARM/subscriptions/$SUB/providers/Microsoft.Security/securityContacts/default?api-version=2023-12-01-preview" \
    --query "{emails:properties.emails,enabled:properties.isEnabled,alertMinSeverity:properties.notificationsSources[0].minimalSeverity}" -o json
  echo; echo "### Sentinel onboarding"
  az rest --method get --url "$SI/onboardingStates?$SIV" --query "value[].{name:name,id:id}" -o table
  echo; echo "### Sentinel analytics rules"
  az rest --method get --url "$SI/alertRules?$SIV" \
    --query "value[].{Rule:properties.displayName,Kind:kind,Severity:properties.severity,Enabled:properties.enabled,Every:properties.queryFrequency}" -o table
} | tee "$EVID/02_threat_detection_evidence.txt"

echo; [ $FAILED -eq 0 ] && echo "DONE. All rules created." || echo "DONE with $FAILED rule(s) not created - tell Claude."
