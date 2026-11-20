#!/usr/bin/env bash
# Step 2 - Governance guardrails (Azure Policy = equivalent of AWS SCPs + tag policies).
#   HVMC-Guardrails      : subscription scope - region lock, storage deny rules, Key Vault audits
#   HVMC-Mandatory-Tags  : HVMC workload RGs - inherit tags from RG (Modify) + deny untagged resources (Deny)
#   HITRUST/HIPAA        : subscription scope - built-in framework initiative, audit only (Config Rules equivalent)
export MSYS_NO_PATHCONV=1
SUB=$(az account show --query id -o tsv | tr -d '\r')
OUT=evidence/02_assign_policies.txt
{
  echo "== Step 2 run: $(date -u +%Y-%m-%dT%H:%MZ)"
  az policy set-definition create -n hvmc-guardrails --display-name "HVMC-Guardrails" \
     --description "HVMC preventive guardrails: approved region, storage encryption/public access, Key Vault audits" \
     --metadata category=HVMC-Governance --definitions policy/hvmc_guardrails.definitions.json --query "{name:name,policies:length(policyDefinitions)}" -o json
  az policy set-definition create -n hvmc-mandatory-tags --display-name "HVMC-Mandatory-Tags" \
     --description "HVMC tag schema: inherit Owner/Environment/DataClassification/CostCenter from RG; deny resources missing mandatory tags" \
     --metadata category=HVMC-Governance --definitions policy/hvmc_mandatory_tags.definitions.json --query "{name:name,policies:length(policyDefinitions)}" -o json

  az policy assignment create -n hvmc-guardrails --display-name "HVMC-Guardrails (subscription)" \
     --policy-set-definition hvmc-guardrails --scope "/subscriptions/$SUB" \
     --non-compliance-messages "[{message:'Blocked by HVMC-Guardrails policy - see Cloud Compliance and Governance Controls v2.0'}]" \
     --query "{name:name,scope:scope,enforcement:enforcementMode}" -o json

  for RG in HVMC-CloudSecurity-RG HVMC-KeyVault-RG; do
    RGID="/subscriptions/$SUB/resourceGroups/$RG"
    az policy assignment create -n "hvmc-tags-${RG,,}" --display-name "HVMC-Mandatory-Tags ($RG)" \
       --policy-set-definition hvmc-mandatory-tags --scope "$RGID" --mi-system-assigned --location eastus \
       --non-compliance-messages "[{message:'Resource is missing an HVMC mandatory tag - Owner, Environment, DataClassification'}]" \
       --query "{name:name,scope:scope,identity:identity.type}" -o json
    PID=$(az policy assignment show -n "hvmc-tags-${RG,,}" --scope "$RGID" --query identity.principalId -o tsv | tr -d '\r')
    sleep 20
    az role assignment create --assignee-object-id "$PID" --assignee-principal-type ServicePrincipal \
       --role "Tag Contributor" --scope "$RGID" --query "{role:roleDefinitionName,scope:scope}" -o json
  done

  az policy assignment create -n hvmc-hipaa-hitrust --display-name "HITRUST/HIPAA (audit only)" \
     --policy-set-definition a169a624-5599-4385-a696-c8d643089fab --scope "/subscriptions/$SUB" \
     --mi-system-assigned --location eastus --query "{name:name,scope:scope}" -o json

  echo; echo "== Policy assignments after Step 2"
  az policy assignment list --query "[].{Name:displayName,Enforcement:enforcementMode}" -o table
} 2>&1 | tr -d '\r' | bash mask.sh > "$OUT"
cat "$OUT"
