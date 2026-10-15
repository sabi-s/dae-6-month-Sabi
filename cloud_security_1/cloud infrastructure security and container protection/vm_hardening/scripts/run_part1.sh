#!/bin/bash
# HVMC Cloud Infrastructure Security - Part 1: build and harden HVMC-App-VM01
# Author: Sabitha S Karanavar
#
# COST (Azure free-trial credit, spending limit ON - no card charge):
#   2-vCPU VM ~$0.08-0.10/h + 30 GB StandardSSD ~$0.003/h  =  about $2-2.50 per day
#   (B2s had no capacity in East US on 2026-10-15, so small sizes are tried in order)
#   No public IP, no new Bastion (uses existing HVMC-Bastion).
# Delete afterwards with:  bash delete_part1.sh
set -euo pipefail
export PATH="$HOME/.azure-cli-env/bin:$PATH" PYTHONWARNINGS=ignore
HERE="$(cd "$(dirname "$0")" && pwd)"; EVID="$HERE/../evidence"; mkdir -p "$EVID"
RG=HVMC-CloudSecurity-RG; VM=HVMC-App-VM01; KEY="$HOME/.ssh/hvmc_vm01"

step() { echo; echo "=== $*"; }
on_vm() {  # run a script on the VM through Azure Run Command (no SSH / public IP needed)
  az vm run-command invoke -g $RG -n $VM --command-id RunShellScript --scripts @"$1" \
     --query "value[0].message" -o tsv
}

step "1/6 SSH key (RSA 4096, accepted by Azure Bastion)"
[ -f "$KEY" ] || ssh-keygen -q -t rsa -b 4096 -N "" -C "hvmcadmin@$VM" -f "$KEY"
chmod 600 "$KEY"; ssh-keygen -lf "$KEY.pub" | tee "$EVID/00_ssh_key_fingerprint.txt"

step "2/6 create VM (App subnet, no public IP, Trusted Launch, key-only)"
if ! az vm show -g $RG -n $VM -o none 2>/dev/null; then
  for SIZE in Standard_D2als_v7 Standard_D2as_v4 Standard_D2ls_v7 Standard_D2s_v4; do
    echo "trying size $SIZE ..."
    if az vm create -g $RG -n $VM --image Canonical:ubuntu-24_04-lts:server:latest --size $SIZE \
        --vnet-name HVMC-Prod-VNet --subnet HVMC-App-Subnet --public-ip-address "" --nsg "" \
        --admin-username hvmcadmin --authentication-type ssh --ssh-key-values "$KEY.pub" \
        --security-type TrustedLaunch --enable-secure-boot true --enable-vtpm true \
        --os-disk-size-gb 30 --storage-sku StandardSSD_LRS \
        --tags Project=HVMC Tier=App Rubric=CloudInfraSecurity \
        --query "{vm:id,privateIp:privateIpAddress,publicIp:publicIpAddress}" -o json \
        > "$EVID/00_vm_create.json" 2> "$EVID/.create_err.txt"; then
      echo "size: $SIZE" >> "$EVID/00_vm_create.json"; cat "$EVID/00_vm_create.json"; rm -f "$EVID/.create_err.txt"
      break
    fi
    grep -oE "(SkuNotAvailable|QuotaExceeded|OperationNotAllowed|InvalidParameter)[^.]*" "$EVID/.create_err.txt" | head -1
  done
  az vm show -g $RG -n $VM -o none 2>/dev/null || { echo "No size available - see $EVID/.create_err.txt"; exit 1; }
fi

step "3/6 Azure Update Manager: periodic patch assessment + on-demand assessment"
az vm update -g $RG -n $VM --set osProfile.linuxConfiguration.patchSettings.assessmentMode=AutomaticByPlatform -o none
az vm assess-patches -g $RG -n $VM \
  --query "{status:status,critical:criticalAndSecurityPatchCount,other:otherPatchCount,started:startDateTime}" -o json \
  | tee "$EVID/00_azure_patch_assessment_before.json"

step "4/6 harden the host (patching, UFW, SSH, fail2ban, sysctl) - takes a few minutes"
on_vm "$HERE/harden_vm.sh" | tee "$EVID/01_hardening_run.txt"

step "5/6 collect evidence from the VM"
for s in "$HERE"/evidence/*.sh; do
  n=$(basename "$s" .sh); echo "--- $n"; on_vm "$s" > "$EVID/$n.txt"; sed -n '1,6p' "$EVID/$n.txt"
done

step "6/6 Azure-side evidence"
{
  echo "### VM security profile and patch settings"
  az vm show -g $RG -n $VM --query "{securityType:securityProfile.securityType,secureBoot:securityProfile.uefiSettings.secureBootEnabled,vTpm:securityProfile.uefiSettings.vTpmEnabled,passwordAuthDisabled:osProfile.linuxConfiguration.disablePasswordAuthentication,patchMode:osProfile.linuxConfiguration.patchSettings.patchMode,assessmentMode:osProfile.linuxConfiguration.patchSettings.assessmentMode}" -o json
  echo; echo "### NIC - private IP only"
  az vm list-ip-addresses -g $RG -n $VM -o table
  echo; echo "### App subnet NSG rules (network layer in front of UFW)"
  az network nsg rule list -g $RG --nsg-name HVMC-App-NSG --include-default -o table --query "[].{Priority:priority,Name:name,Dir:direction,Access:access,Src:sourceAddressPrefix,Port:destinationPortRange}"
  echo; echo "### patch assessment after hardening"
  az vm assess-patches -g $RG -n $VM --query "{status:status,critical:criticalAndSecurityPatchCount,other:otherPatchCount}" -o json
} | tee "$EVID/06_azure_side.txt"

echo; echo "DONE. Evidence saved in: $EVID"
