#!/usr/bin/env bash
# Step 5b - One-time tag backfill.
# Why: the Step 5 remediation tasks add ONE inherited tag per request, but the Require-<tag> Deny rules check that ALL
# three mandatory tags are present on every request - so 7 of 8 tasks were refused by policy (evidence in
# 05_remediation_failures.txt). This script copies the full RG tag set to each resource in ONE request, which passes the
# Deny rules. New resources are tagged automatically by the Modify rules at creation time (proved in 04b).
export MSYS_NO_PATHCONV=1
OUT=evidence/05b_backfill_tags.txt
{
  echo "== Step 5b run: $(date -u +%Y-%m-%dT%H:%MZ)"
  for RG in HVMC-CloudSecurity-RG HVMC-KeyVault-RG; do
    O=$(az group show -n $RG --query "tags.Owner || tags.owner" -o tsv | tr -d '\r')
    E=$(az group show -n $RG --query tags.Environment -o tsv | tr -d '\r')
    D=$(az group show -n $RG --query tags.DataClassification -o tsv | tr -d '\r')
    C=$(az group show -n $RG --query tags.CostCenter -o tsv | tr -d '\r')
    for ID in $(az resource list -g $RG --query "[].id" -o tsv | tr -d '\r'); do
      if az tag update --operation Merge --resource-id "$ID" --tags Owner=$O Environment=$E DataClassification=$D CostCenter=$C -o none 2>/tmp/tagerr; then
        echo "TAGGED  $RG/${ID##*/}"
      else
        echo "FAILED  $RG/${ID##*/}: $(head -1 /tmp/tagerr)"
      fi
    done
  done
  echo; echo "Missing mandatory tags (all RGs): $(az resource list --query 'length([?tags.Owner==null || tags.Environment==null || tags.DataClassification==null])' -o tsv)"
  az resource list --query "[?tags.Owner==null || tags.Environment==null || tags.DataClassification==null].{Name:name,RG:resourceGroup}" -o table
  echo; echo "-- Starting a new compliance scan"; az policy state trigger-scan --no-wait
} 2>&1 | tr -d '\r' | bash mask.sh > "$OUT"
cat "$OUT"
