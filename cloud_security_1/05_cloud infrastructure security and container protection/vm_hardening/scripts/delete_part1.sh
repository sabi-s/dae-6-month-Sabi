#!/bin/bash
# Removes HVMC-App-VM01 and its NIC and OS disk (stops the ~$1.10/day credit use).
set -uo pipefail
export PATH="$HOME/.azure-cli-env/bin:$PATH" PYTHONWARNINGS=ignore
RG=HVMC-CloudSecurity-RG; VM=HVMC-App-VM01
NIC=$(az vm show -g $RG -n $VM --query "networkProfile.networkInterfaces[0].id" -o tsv)
DISK=$(az vm show -g $RG -n $VM --query "storageProfile.osDisk.managedDisk.id" -o tsv)
az vm delete -g $RG -n $VM --yes && az network nic delete --ids "$NIC" && az disk delete --ids "$DISK" --yes
echo "deleted $VM, NIC and OS disk"
