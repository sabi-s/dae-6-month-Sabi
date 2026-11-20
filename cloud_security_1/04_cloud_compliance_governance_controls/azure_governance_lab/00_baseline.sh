#!/usr/bin/env bash
# Step 0 - Baseline: record the governance state BEFORE any change (read-only).
export MSYS_NO_PATHCONV=1
OUT=evidence/00_baseline.txt
{
  echo "== Baseline captured: $(date -u +%Y-%m-%dT%H:%MZ)"
  echo; echo "== Policy assignments"
  az policy assignment list --query "[].{Name:displayName,Enforcement:enforcementMode}" -o table
  echo; echo "== Resource groups and tags"
  az group list --query "[].{Name:name,Location:location,Tags:tags}" -o json
  echo; echo "== Resources without Owner/Environment/DataClassification tags"
  az resource list --query "[?tags.Owner==null || tags.Environment==null || tags.DataClassification==null].{Name:name,RG:resourceGroup,Type:type}" -o table
  echo; echo "Total resources: $(az resource list --query 'length(@)' -o tsv)"
  echo "Resources missing mandatory tags: $(az resource list --query 'length([?tags.Owner==null || tags.Environment==null || tags.DataClassification==null])' -o tsv)"
  echo; echo "== Resource locks"
  az lock list --query "[].{Name:name,Level:level,Scope:id}" -o table
} 2>&1 | tr -d '\r' | bash mask.sh > "$OUT"
cat "$OUT"
