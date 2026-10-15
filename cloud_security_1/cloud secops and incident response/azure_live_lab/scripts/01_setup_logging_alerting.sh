#!/bin/bash
# HVMC Cloud Security Operations & Incident Response - Step 1
# Centralised logging, VNet flow logs and automated security alerting
# Horizon Valley Medical Center | Author: Sabitha S Karanavar
#
# AWS rubric term      -> what this script builds in Azure
#   CloudTrail         -> Activity Log (subscription) + Bastion, NSG and ePHI-storage resource logs
#                         -> one Log Analytics workspace (HVMC-SecOps-LAW)
#   VPC Flow Logs      -> VNet flow logs on HVMC-Prod-VNet + Traffic Analytics
#   Automated alerting -> 9 activity-log alert rules -> action group -> e-mail
#   (cost guard)       -> $10 subscription budget that e-mails at 50/80/100 %
#
# COST (free-trial credit, spending limit ON - no card charge), expected < $0.10 in total:
#   Log Analytics: first 5 GB/month free; daily cap 0.5 GB set as a guard
#   Flow logs $0.50/GB + Traffic Analytics $2.30/GB processed: a few MB here (no VMs running)
#   Log storage account (Standard LRS): cents.  Activity-log alerts, action group e-mail, budget: free
# Remove everything with:  bash 99_teardown.sh
set -euo pipefail
export PATH="$HOME/.azure-cli-env/bin:$PATH" PYTHONWARNINGS=ignore
HERE="$(cd "$(dirname "$0")" && pwd)"; EVID="$HERE/../evidence"; mkdir -p "$EVID"

ALERT_EMAIL="sabithaskaranavar@gmail.com"
SUB=$(az account show --query id -o tsv)
RG=HVMC-CloudSecurity-RG; LOC=eastus
LAW=HVMC-SecOps-LAW
LOGSA=hvmcseclogs${SUB:0:6}          # flow-log storage, kept separate from the ePHI account
AG=HVMC-SecOps-AG
SUBSCOPE=/subscriptions/$SUB

step() { echo; echo "=== $*"; }

step "1/8 register resource providers (free)"
for p in Microsoft.Insights Microsoft.OperationalInsights Microsoft.OperationsManagement Microsoft.AlertsManagement; do
  az provider register --namespace $p --wait -o none; echo "  $p registered"
done

step "2/8 Log Analytics workspace $LAW (30-day retention, 0.5 GB/day cap)"
az monitor log-analytics workspace create -g $RG -n $LAW -l $LOC --sku PerGB2018 --retention-time 30 \
   --quota 0.5 --tags Project=HVMC Rubric=SecOpsIR -o none
LAW_ID=$(az monitor log-analytics workspace show -g $RG -n $LAW --query id -o tsv)
echo "  $LAW_ID"

step "3/8 Activity Log (subscription control plane = CloudTrail equivalent) -> workspace"
az monitor diagnostic-settings subscription create --name HVMC-ActivityLog-to-LAW --location $LOC \
  --workspace "$LAW_ID" --logs '[
    {"category":"Administrative","enabled":true},{"category":"Security","enabled":true},
    {"category":"ServiceHealth","enabled":true},{"category":"Alert","enabled":true},
    {"category":"Recommendation","enabled":true},{"category":"Policy","enabled":true},
    {"category":"Autoscale","enabled":true},{"category":"ResourceHealth","enabled":true}]' -o none
echo "  8 activity-log categories streaming"

step "4/8 resource logs -> workspace (Bastion sessions, NSG events, ePHI blob access)"
az monitor diagnostic-settings create -n HVMC-to-LAW --workspace "$LAW_ID" \
  --resource $(az network bastion show -g $RG -n HVMC-Bastion --query id -o tsv) \
  --logs '[{"category":"BastionAuditLogs","enabled":true}]' -o none && echo "  Bastion audit logs"
for nsg in HVMC-Web-NSG HVMC-App-NSG HVMC-Data-NSG; do
  az monitor diagnostic-settings create -n HVMC-to-LAW --workspace "$LAW_ID" \
    --resource $(az network nsg show -g $RG -n $nsg --query id -o tsv) \
    --logs '[{"category":"NetworkSecurityGroupEvent","enabled":true},{"category":"NetworkSecurityGroupRuleCounter","enabled":true}]' -o none
  echo "  $nsg events"
done
az monitor diagnostic-settings create -n HVMC-ePHI-access-to-LAW --workspace "$LAW_ID" \
  --resource "$(az storage account show -g $RG -n hvmcehrstorage --query id -o tsv)/blobServices/default" \
  --logs '[{"category":"StorageRead","enabled":true},{"category":"StorageWrite","enabled":true},{"category":"StorageDelete","enabled":true}]' -o none
echo "  hvmcehrstorage blob read/write/delete (HIPAA 164.312(b) audit controls)"

step "5/8 VNet flow logs (VPC Flow Logs equivalent) + Traffic Analytics"
if ! az storage account show -g $RG -n $LOGSA -o none 2>/dev/null; then
  az storage account create -g $RG -n $LOGSA -l $LOC --sku Standard_LRS --kind StorageV2 \
    --min-tls-version TLS1_2 --allow-blob-public-access false --https-only true \
    --tags Project=HVMC Purpose=SecurityLogs -o none
fi
LOGSA_ID=$(az storage account show -g $RG -n $LOGSA --query id -o tsv)
az network watcher flow-log create --location $LOC -g $RG --name HVMC-Prod-VNet-FlowLog \
  --vnet HVMC-Prod-VNet --storage-account "$LOGSA_ID" --retention 30 \
  --traffic-analytics true --workspace "$LAW_ID" --interval 10 -o none
echo "  flow log -> $LOGSA (30-day retention), Traffic Analytics every 10 min -> $LAW"

step "6/8 action group $AG (e-mail $ALERT_EMAIL)"
az monitor action-group create -g $RG -n $AG --short-name HVMCSecOps \
  --action email SecurityLead "$ALERT_EMAIL" usecommonalertschema -o none
AG_ID=$(az monitor action-group show -g $RG -n $AG --query id -o tsv)

step "7/8 security alert rules (activity-log alerts, free)"
mk_alert() {  # name  condition  description
  az monitor activity-log alert create -g $RG -n "$1" --scope $SUBSCOPE --condition "$2" \
    --action-group "$AG_ID" --description "$3" -o none
  echo "  $1"
}
mk_alert "HVMC-NSG-Rule-Changed"      "category=Administrative and operationName=Microsoft.Network/networkSecurityGroups/securityRules/write" \
  "Firewall rule created or modified (risk R03) - check for Internet-facing allow rules. IR playbook PB-01."
mk_alert "HVMC-NSG-Rule-Deleted"      "category=Administrative and operationName=Microsoft.Network/networkSecurityGroups/securityRules/delete" \
  "Firewall rule deleted (risk R03). IR playbook PB-01."
mk_alert "HVMC-Role-Assignment-Added" "category=Administrative and operationName=Microsoft.Authorization/roleAssignments/write" \
  "New Azure RBAC role assignment - possible privilege escalation (risk R04). IR playbook PB-02."
mk_alert "HVMC-Role-Assignment-Removed" "category=Administrative and operationName=Microsoft.Authorization/roleAssignments/delete" \
  "RBAC role assignment removed (risk R04). IR playbook PB-02."
mk_alert "HVMC-Storage-Config-Changed" "category=Administrative and operationName=Microsoft.Storage/storageAccounts/write" \
  "Storage account configuration changed - ePHI exposure check (risk R02). IR playbook PB-03."
mk_alert "HVMC-Storage-Keys-Listed"   "category=Administrative and operationName=Microsoft.Storage/storageAccounts/listKeys/action" \
  "Storage account keys retrieved - possible credential access to ePHI (risk R02, R05). IR playbook PB-03."
mk_alert "HVMC-Public-IP-Created"     "category=Administrative and operationName=Microsoft.Network/publicIPAddresses/write" \
  "New public IP - new Internet exposure (risk R03, R10). IR playbook PB-01."
mk_alert "HVMC-Diagnostic-Setting-Deleted" "category=Administrative and operationName=Microsoft.Insights/diagnosticSettings/delete" \
  "Security logging disabled - possible defence evasion (MITRE T1562.008). IR playbook PB-04."
mk_alert "HVMC-Defender-Security-Alert" "category=Security" \
  "Microsoft Defender for Cloud raised a security alert. IR playbook per alert type."

step "8/8 cost guard: \$10 budget, e-mail at 50 / 80 / 100 %"
START=$(date -u +%Y-%m-01)
az rest --method put -o none \
  --url "https://management.azure.com$SUBSCOPE/providers/Microsoft.Consumption/budgets/HVMC-Lab-Budget?api-version=2023-05-01" \
  --body "{\"properties\":{\"category\":\"Cost\",\"amount\":10,\"timeGrain\":\"Monthly\",
     \"timePeriod\":{\"startDate\":\"${START}T00:00:00Z\",\"endDate\":\"2027-09-30T00:00:00Z\"},
     \"notifications\":{
       \"at50\":{\"enabled\":true,\"operator\":\"GreaterThan\",\"threshold\":50,\"contactEmails\":[\"$ALERT_EMAIL\"]},
       \"at80\":{\"enabled\":true,\"operator\":\"GreaterThan\",\"threshold\":80,\"contactEmails\":[\"$ALERT_EMAIL\"]},
       \"at100\":{\"enabled\":true,\"operator\":\"GreaterThan\",\"threshold\":100,\"contactEmails\":[\"$ALERT_EMAIL\"]}}}}"
echo "  HVMC-Lab-Budget created"

step "evidence"
{
  echo "### Log Analytics workspace"
  az monitor log-analytics workspace show -g $RG -n $LAW -o json \
    --query "{name:name,location:location,sku:sku.name,retentionDays:retentionInDays,dailyCapGB:workspaceCapping.dailyQuotaGb}"
  echo; echo "### Subscription Activity Log export"
  az monitor diagnostic-settings subscription list -o json --query "value[].{name:name,workspace:workspaceId,categories:logs[?enabled].category}"
  echo; echo "### Resource diagnostic settings"
  for r in $(az network nsg list -g $RG --query "[].id" -o tsv) $(az network bastion show -g $RG -n HVMC-Bastion --query id -o tsv); do
    az monitor diagnostic-settings list --resource "$r" -o tsv --query "[].[name, join(',', logs[?enabled].category)]" | sed "s|^|${r##*/}  |"
  done
  az monitor diagnostic-settings list --resource "$(az storage account show -g $RG -n hvmcehrstorage --query id -o tsv)/blobServices/default" \
    -o tsv --query "[].[name, join(',', logs[?enabled].category)]" | sed "s|^|hvmcehrstorage/blob  |"
  echo; echo "### VNet flow log"
  az network watcher flow-log show --location $LOC -n HVMC-Prod-VNet-FlowLog -o json \
    --query "{name:name,target:targetResourceId,enabled:enabled,retentionDays:retentionPolicy.days,trafficAnalytics:flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled,intervalMin:flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.trafficAnalyticsInterval}"
  echo; echo "### Alert rules"
  az monitor activity-log alert list -g $RG -o table --query "[].{Name:name,Enabled:enabled,Operation:condition.allOf[1].equals || condition.allOf[0].equals}"
  echo; echo "### Action group"
  az monitor action-group show -g $RG -n $AG -o json --query "{name:name,enabled:enabled,email:emailReceivers[].{name:name,status:status}}"
} | tee "$EVID/01_setup_evidence.txt"

echo; echo "DONE. Evidence: $EVID/01_setup_evidence.txt"
echo "Azure will e-mail $ALERT_EMAIL to confirm the action group - no click needed, it is informational."
