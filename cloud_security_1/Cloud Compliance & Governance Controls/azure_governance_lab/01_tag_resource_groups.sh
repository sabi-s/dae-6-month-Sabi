#!/usr/bin/env bash
# Step 1 - Mandatory tag set on the resource groups (merge: existing tags are kept).
# Tag schema: Owner, Environment, DataClassification (mandatory) + CostCenter (recommended).
export MSYS_NO_PATHCONV=1
OUT=evidence/01_tag_resource_groups.txt
{
  echo "== Step 1 run: $(date -u +%Y-%m-%dT%H:%MZ)"
  az tag update --operation Merge --resource-id "$(az group show -n HVMC-CloudSecurity-RG --query id -o tsv | tr -d '\r')" \
     --tags Owner=IAM-Admin Environment=lab DataClassification=ephi-simulated CostCenter=hvmc-capstone -o json
  az tag update --operation Merge --resource-id "$(az group show -n HVMC-KeyVault-RG --query id -o tsv | tr -d '\r')" \
     --tags Owner=IAM-Admin Environment=lab DataClassification=secrets CostCenter=hvmc-capstone -o json
  az tag update --operation Merge --resource-id "$(az group show -n NetworkWatcherRG --query id -o tsv | tr -d '\r')" \
     --tags Owner=IAM-Admin Environment=lab DataClassification=internal CostCenter=hvmc-capstone -o json
  echo; echo "== Resource groups after tagging"
  az group list --query "[].{Name:name,Owner:tags.Owner,Environment:tags.Environment,DataClassification:tags.DataClassification,CostCenter:tags.CostCenter}" -o table
} 2>&1 | tr -d '\r' | bash mask.sh > "$OUT"
tail -8 "$OUT"
