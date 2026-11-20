#!/usr/bin/env bash
# Masks subscription ID, tenant ID, account e-mail and object IDs before evidence is saved to the repo.
SUB=$(az account show --query id -o tsv | tr -d '\r')
TEN=$(az account show --query tenantId -o tsv | tr -d '\r')
USR=$(az account show --query user.name -o tsv | tr -d '\r')
sed -e "s/$SUB/<sub-id>/g" -e "s/$TEN/<tenant-id>/g" -e "s/${USR//./\.}/<admin-email>/g" -e "s/live\.com#//g" \
    -e 's/"principalId": "[0-9a-f-]\{36\}"/"principalId": "<id>"/g'
