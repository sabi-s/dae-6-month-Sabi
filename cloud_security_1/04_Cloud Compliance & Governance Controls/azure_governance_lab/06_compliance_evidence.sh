#!/usr/bin/env bash
# Step 6 - Collect compliance results after the scan and the tag backfill (read-only).
# Uses the LATEST policy state of each resource (no --all, which would also return historical states).
export MSYS_NO_PATHCONV=1
E=evidence
{
  echo "== Step 6 run: $(date -u +%Y-%m-%dT%H:%MZ)"
  echo; echo "== Remediation tasks (tag inheritance) - see 05_remediation_failures.txt for why 7 of 8 failed"
  for RG in HVMC-CloudSecurity-RG HVMC-KeyVault-RG; do
    az policy remediation list -g $RG --query "[?starts_with(name,'hvmc-inherit')].{Task:name,State:provisioningState}" -o table
  done
  echo; echo "== Resources missing mandatory tags (after backfill)"
  echo "Total resources: $(az resource list --query 'length(@)' -o tsv)"
  echo "Missing Owner/Environment/DataClassification: $(az resource list --query 'length([?tags.Owner==null || tags.Environment==null || tags.DataClassification==null])' -o tsv)"
  echo; echo "== Compliance by assignment (latest states)"
  az policy state summarize --query "policyAssignments[].{Assignment:policyAssignmentId,NonCompliantResources:results.nonCompliantResources,NonCompliantPolicies:results.nonCompliantPolicies}" -o tsv \
     | sed -E 's#.*/policyassignments/##'
  echo; echo "== HVMC-Guardrails: non-compliant resources by rule (latest states)"
  az policy state list --top 5000 --filter "policyAssignmentName eq 'hvmc-guardrails' and complianceState eq 'NonCompliant'" \
     --query "[].{Rule:policyDefinitionReferenceId,Resource:resourceId}" -o tsv | sed -E 's#\t.*/#\t#'
  echo; echo "== Policy deny events in the activity log (lab day, from 18:55 UTC; time  resource)"
  az monitor activity-log list --start-time 2026-11-20T18:55:00Z --max-events 3000 \
     --query "[?operationName.value=='Microsoft.Authorization/policies/deny/action'].[eventTimestamp,resourceId]" -o tsv \
     | sed -E 's#\t.*/#\t#' | sort > /tmp/hvmc_denies.txt
  echo "Deny events: $(wc -l < /tmp/hvmc_denies.txt)"
  awk -F'\t' '{print substr($1,12,8)"  "$2}' /tmp/hvmc_denies.txt
} 2>&1 | tr -d '\r' | bash mask.sh > $E/06_compliance_results.txt

az policy state summarize --policy-assignment hvmc-hipaa-hitrust -o json 2>/dev/null | tr -d '\r' | bash mask.sh > $E/06_hipaa_summary.json
cat $E/06_compliance_results.txt
