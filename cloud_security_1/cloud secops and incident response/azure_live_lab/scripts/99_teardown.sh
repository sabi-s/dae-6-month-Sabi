#!/bin/bash
# Removes everything 01_setup_logging_alerting.sh created. Leaves the original HVMC lab untouched.
set -uo pipefail
export PATH="$HOME/.azure-cli-env/bin:$PATH" PYTHONWARNINGS=ignore
SUB=$(az account show --query id -o tsv); RG=HVMC-CloudSecurity-RG; LOC=eastus

# Step 2: Defender plans back to Free (stops any post-trial charge); Sentinel goes with the workspace below
for p in StorageAccounts Arm; do
  az rest --method put -o none --url "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Security/pricings/$p?api-version=2024-01-01" \
    --body '{"properties":{"pricingTier":"Free"}}' && echo "Defender $p -> Free"; done
LAW_ID=$(az monitor log-analytics workspace show -g $RG -n HVMC-SecOps-LAW --query id -o tsv 2>/dev/null)
[ -n "$LAW_ID" ] && az rest --method delete --url "https://management.azure.com$LAW_ID/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01" && echo "Sentinel removed"

# Step 1
for a in $(az monitor activity-log alert list -g $RG --query "[?starts_with(name,'HVMC-')].name" -o tsv); do
  az monitor activity-log alert delete -g $RG -n "$a" && echo "alert $a deleted"; done
az monitor action-group delete -g $RG -n HVMC-SecOps-AG && echo "action group deleted"
az network watcher flow-log delete --location $LOC -n HVMC-Prod-VNet-FlowLog && echo "flow log deleted"
az monitor diagnostic-settings subscription delete -n HVMC-ActivityLog-to-LAW --yes && echo "activity log export deleted"
for r in $(az network nsg list -g $RG --query "[].id" -o tsv) $(az network bastion show -g $RG -n HVMC-Bastion --query id -o tsv); do
  az monitor diagnostic-settings delete -n HVMC-to-LAW --resource "$r" 2>/dev/null && echo "diag ${r##*/} deleted"; done
az monitor diagnostic-settings delete -n HVMC-ePHI-access-to-LAW \
  --resource "$(az storage account show -g $RG -n hvmcehrstorage --query id -o tsv)/blobServices/default" && echo "ePHI diag deleted"
az storage account delete -g $RG -n hvmcseclogs${SUB:0:6} --yes && echo "log storage deleted"
az monitor log-analytics workspace delete -g $RG -n HVMC-SecOps-LAW --force --yes && echo "workspace deleted"
az rest --method delete --url "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Consumption/budgets/HVMC-Lab-Budget?api-version=2023-05-01" && echo "budget deleted"

# Step 3: workbook
WB_ID=$(python3 -c "import uuid; print(uuid.uuid5(uuid.NAMESPACE_URL, 'hvmc-secops-workbook'))")
az rest --method delete --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Insights/workbooks/$WB_ID?api-version=2022-04-01" && echo "workbook deleted"
