#!/usr/bin/env bash
# Step 4 - Enforcement tests. Each request breaks one HVMC rule and is expected to be refused by Azure Policy
# (RequestDisallowedByPolicy) before anything is created, so no cost is incurred.
export MSYS_NO_PATHCONV=1
OUT=evidence/04_enforcement_tests.txt
N=hvmcpolicytest$RANDOM
t() { echo; echo "---- TEST $1: $2"; echo "Expected: DENIED by $3"; shift 3
      R=$("$@" -o none 2>&1); RC=$?
      echo "$R" | grep -E "RequestDisallowedByPolicy|policyDefinitionReferenceId" | head -5
      if [ $RC -ne 0 ] && echo "$R" | grep -q RequestDisallowedByPolicy; then echo "RESULT: DENIED by policy (as expected)"; else echo "RESULT: NOT DENIED - review"; fi; }
# Note: a TLS 1.0 test is not included - Azure retired TLS 1.0/1.1 on 2026-02-03 and the CLI silently upgrades the
# request to TLS 1.2 (see evidence/04b_test5_followup.txt).
{
  echo "== Step 4 run: $(date -u +%Y-%m-%dT%H:%MZ)"
  t 1 "Create a resource group outside the approved region (westus)" "Restrict-Regions-ResourceGroups" \
      az group create -n HVMC-PolicyTest-RG -l westus --tags Owner=IAM-Admin Environment=lab DataClassification=internal
  t 2 "Create a storage account in westus" "Restrict-Regions" \
      az storage account create -n $N -g HVMC-CloudSecurity-RG -l westus --sku Standard_LRS
  t 3 "Create a storage account that allows public blob access" "Deny-Public-Storage" \
      az storage account create -n $N -g HVMC-CloudSecurity-RG -l eastus --sku Standard_LRS --allow-blob-public-access true
  t 4 "Create a storage account with HTTP (non-TLS) traffic allowed" "Deny-Insecure-Transfer" \
      az storage account create -n $N -g HVMC-CloudSecurity-RG -l eastus --sku Standard_LRS --https-only false --allow-blob-public-access false
} 2>&1 | tr -d '\r' | bash mask.sh > "$OUT"
cat "$OUT"
