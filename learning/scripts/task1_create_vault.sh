#!/bin/bash
# Azure Key Vault - Task 1 (learning/PLAN.md): RBAC-enabled vault with soft delete + purge protection, 2 dummy secrets.
# HVMC / AccessGuard Health - Author: Sabitha S Karanavar
# Usage: ./task1_create_vault.sh           dry run (read-only checks, changes nothing)
#        ./task1_create_vault.sh --apply   create everything
# Secret values are random, written to a 0600 temp file for the upload, never printed, and the file is deleted.
export PATH=~/.azure-cli-env/bin:$PATH
set -u
RG=HVMC-KeyVault-RG; KV=hvmc-accessguard-kv; LOC=eastus
SECRETS="servicenow-lab-password accessguard-api-key"
TAGS="project=HVMC-AccessGuard owner=IAM-Admin purpose=learning-keyvault data=dummy-only"
APPLY=0; [ "${1:-}" = "--apply" ] && APPLY=1
SUB=$(az account list --all --query "[?name=='Azure subscription 1'].id | [0]" -o tsv); A="--subscription $SUB"
EVID="$(cd "$(dirname "$0")" && pwd)/evidence"; mkdir -p "$EVID"; chmod 700 "$EVID"
ME=$(az ad signed-in-user show --query id -o tsv)
FAILED=0
step() { local d="$1"; shift
  if [ $APPLY = 1 ]; then if "$@" > "$EVID/.last" 2>&1; then echo "  ✅ $d"; else echo "  ❌ $d"; sed 's/^/     /' "$EVID/.last" | head -4; FAILED=1; fi
  else echo "  [dry run] would: $d"; fi; }

echo "Task 1 - Key Vault  ($( [ $APPLY = 1 ] && echo APPLY || echo 'DRY RUN - nothing changes'))"
echo "  subscription state : $(az account show $A --query state -o tsv)"
echo "  provider KeyVault  : $(az provider show $A -n Microsoft.KeyVault --query registrationState -o tsv)"
NAMEBODY='{"name":"'$KV'","type":"Microsoft.KeyVault/vaults"}'
FREE=$(az rest --method post --headers Content-Type=application/json --url "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.KeyVault/checkNameAvailability?api-version=2023-07-01" --body "$NAMEBODY" --query nameAvailable -o tsv 2>/dev/null)
echo "  vault name free    : ${FREE:-unknown (provider not registered yet)}"
echo "  cost               : Standard tier, no monthly fee, ~\$0.03 per 10,000 operations"
echo

step "register the Microsoft.KeyVault provider (free, one time)" az provider register $A -n Microsoft.KeyVault --wait
step "create resource group $RG in $LOC" az group create $A -n $RG -l $LOC --tags $TAGS
step "create vault $KV: Standard, Azure RBAC, soft delete 7 days, purge protection ON" \
  az keyvault create $A -g $RG -n $KV -l $LOC --sku standard --enable-rbac-authorization true \
     --retention-days 7 --enable-purge-protection true --tags $TAGS
VID=$(az keyvault show $A -n $KV --query id -o tsv 2>/dev/null)
step "give YOU 'Key Vault Secrets Officer' on this vault only (needed to write secrets with RBAC)" \
  az role assignment create $A --assignee-object-id "$ME" --assignee-principal-type User \
     --role "Key Vault Secrets Officer" --scope "${VID:-/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.KeyVault/vaults/$KV}"
if [ $APPLY = 1 ]; then echo "  ... waiting 60 s for the role to take effect"; sleep 60; fi
for s in $SECRETS; do
  if [ $APPLY = 1 ]; then
    tmp=$(mktemp); chmod 600 "$tmp"; python3 -c "import secrets,sys; sys.stdout.write(secrets.token_urlsafe(24))" > "$tmp"
    step "store dummy secret '$s' (random value, never shown)" \
      az keyvault secret set --vault-name $KV -n $s --file "$tmp" --encoding utf-8 --content-type "dummy lab value" --tags data=dummy --query id -o tsv
    rm -f "$tmp"
  else step "store dummy secret '$s' (random value, never shown)"; fi
done

if [ $APPLY = 1 ]; then
  echo; echo "Proof (PLAN.md success criteria):"
  az keyvault show $A -n $KV --query "{name:name,sku:properties.sku.name,rbacAuthorization:properties.enableRbacAuthorization,softDelete:properties.enableSoftDelete,retentionDays:properties.softDeleteRetentionInDays,purgeProtection:properties.enablePurgeProtection}" -o table | tee "$EVID/keyvault_show.txt"
  for s in $SECRETS; do
    az keyvault secret show --vault-name $KV -n $s --query "{name:name,enabled:attributes.enabled,created:attributes.created,contentType:contentType,value:value}" -o json \
      | python3 -c "import json,sys; d=json.load(sys.stdin); d['value']=d['value'][:3]+'*****  (masked, '+str(len(d['value']))+' chars)'; print(json.dumps(d,indent=2))" | tee "$EVID/secret_show_$s.txt"
  done
  az role assignment list $A --scope "$VID" --query "[].{role:roleDefinitionName,type:principalType}" -o table | tee "$EVID/role_assignments.txt"
  rm -f "$EVID/.last"
fi
exit $FAILED
