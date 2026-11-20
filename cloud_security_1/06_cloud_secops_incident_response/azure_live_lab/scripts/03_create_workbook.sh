#!/bin/bash
# HVMC Cloud Security Operations & Incident Response - Step 3
# Security dashboard in Azure: an Azure Monitor Workbook with 10 KQL tiles over HVMC-SecOps-LAW
# Horizon Valley Medical Center | Author: Sabitha S Karanavar
#
# COST: $0. Azure Workbooks are free; the tiles only run queries against data already collected.
# Remove with: az monitor app-insights workbook delete ... or 99_teardown.sh
set -euo pipefail
export PATH="$HOME/.azure-cli-env/bin:$PATH" PYTHONWARNINGS=ignore AZURE_CORE_ONLY_SHOW_ERRORS=true
HERE="$(cd "$(dirname "$0")" && pwd)"; DASH="$HERE/../dashboard"; EVID="$HERE/../evidence"
RG=HVMC-CloudSecurity-RG
SUB=$(az account show --query id -o tsv)
LAW_ID=$(az monitor log-analytics workspace show -g $RG -n HVMC-SecOps-LAW --query id -o tsv)
WB_ID=$(python3 -c "import uuid; print(uuid.uuid5(uuid.NAMESPACE_URL, 'hvmc-secops-workbook'))")

echo "=== 1/2 build workbook definition (10 tiles, time-range picker)"
python3 "$DASH/make_workbook.py" "$LAW_ID"

echo "=== 2/2 create workbook 'HVMC Security Operations' in $RG"
python3 - "$DASH/hvmc_secops_workbook.json" "$LAW_ID" > "$EVID/.workbook_body.json" <<'EOF'
import json, sys
wb = json.load(open(sys.argv[1]))
print(json.dumps({"location": "eastus", "kind": "shared", "tags": {"Project": "HVMC", "Rubric": "SecOpsIR"},
                  "properties": {"displayName": "HVMC Security Operations", "category": "workbook",
                                 "sourceId": sys.argv[2], "serializedData": json.dumps(wb)}}))
EOF
az rest --method put -o none \
  --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Insights/workbooks/$WB_ID?api-version=2022-04-01" \
  --body @"$EVID/.workbook_body.json"
rm -f "$EVID/.workbook_body.json"

az rest --method get --url "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Insights/workbooks/$WB_ID?api-version=2022-04-01" \
  --query "{name:properties.displayName,category:properties.category,kind:kind,source:properties.sourceId,updated:properties.timeModified}" -o json \
  | tee "$EVID/03_workbook_evidence.txt"
echo
echo "DONE. Open it: Azure portal -> Monitor -> Workbooks -> 'HVMC Security Operations'"
echo "      (or Microsoft Sentinel -> Workbooks -> My workbooks)"
