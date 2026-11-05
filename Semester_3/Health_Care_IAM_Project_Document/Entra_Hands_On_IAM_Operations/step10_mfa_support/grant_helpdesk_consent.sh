#!/bin/bash
# HVMC Step 10 - one-time admin approval, run by the Global Admin (Azure CLI sign-in).
# Approves "Microsoft Graph Command Line Tools" for helpdesk.admin ONLY (consentType Principal), so the MFA help-desk
# script can sign in as the least-privileged help-desk account. What helpdesk.admin can really do is still limited by
# its roles (Authentication Administrator + Reports Reader).
# Undo: ./grant_helpdesk_consent.sh --undo
export PATH=~/.azure-cli-env/bin:$PATH
set -e
G=https://graph.microsoft.com/v1.0
APP=14d82eec-204b-4c2f-b7e8-296a70dab67e          # Microsoft Graph Command Line Tools (Microsoft's own app)
SC="openid profile offline_access User.ReadWrite.All UserAuthenticationMethod.ReadWrite.All AuditLog.Read.All Directory.Read.All RoleManagement.Read.Directory"

HD=$(az rest --method get --url "$G/users?\$filter=startswith(userPrincipalName,'helpdesk.admin@')&\$select=id" --query "value[0].id" -o tsv)
[ -z "$HD" ] && { echo "helpdesk.admin not found"; exit 1; }
SP=$(az rest --method get --url "$G/servicePrincipals?\$filter=appId eq '$APP'&\$select=id" --query "value[0].id" -o tsv)

if [ "$1" = "--undo" ]; then
  EX=$(az rest --method get --url "$G/oauth2PermissionGrants?\$filter=clientId eq '$SP' and principalId eq '$HD'" --query "value[0].id" -o tsv)
  [ -n "$EX" ] && az rest --method delete --url "$G/oauth2PermissionGrants/$EX" && echo "approval removed" || echo "nothing to remove"
  exit 0
fi

echo "This will:"
echo "  1. add Microsoft Graph Command Line Tools to the tenant (if missing)"
echo "  2. approve these permissions for helpdesk.admin ONLY:"
echo "     $SC"
read -r -p "Type YES to continue: " ok
[ "$ok" = "YES" ] || { echo "Cancelled - nothing changed."; exit 0; }

if [ -z "$SP" ]; then
  SP=$(az rest --method post --url "$G/servicePrincipals" --headers Content-Type=application/json --body "{\"appId\":\"$APP\"}" --query id -o tsv)
  echo "  ✅ 1. Graph Command Line Tools added to the tenant"
else
  echo "  ✅ 1. Graph Command Line Tools already in the tenant"
fi
GRAPH=$(az rest --method get --url "$G/servicePrincipals?\$filter=appId eq '00000003-0000-0000-c000-000000000000'&\$select=id" --query "value[0].id" -o tsv)
EX=$(az rest --method get --url "$G/oauth2PermissionGrants?\$filter=clientId eq '$SP' and principalId eq '$HD'" --query "value[0].id" -o tsv)
if [ -n "$EX" ]; then
  az rest --method patch --url "$G/oauth2PermissionGrants/$EX" --headers Content-Type=application/json --body "{\"scope\":\"$SC\"}" > /dev/null
  echo "  ✅ 2. approval updated for helpdesk.admin"
else
  az rest --method post --url "$G/oauth2PermissionGrants" --headers Content-Type=application/json \
    --body "{\"clientId\":\"$SP\",\"consentType\":\"Principal\",\"principalId\":\"$HD\",\"resourceId\":\"$GRAPH\",\"scope\":\"$SC\"}" > /dev/null
  echo "  ✅ 2. approval created for helpdesk.admin only"
fi
echo
echo "Check (consentType should be Principal, forHelpdeskOnly true):"
az rest --method get --url "$G/oauth2PermissionGrants?\$filter=clientId eq '$SP'" \
  --query "value[].{consentType:consentType,forHelpdeskOnly:principalId=='$HD'}" -o table
