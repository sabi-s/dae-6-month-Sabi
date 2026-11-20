#!/bin/bash
# HVMC Cloud Security Operations & Incident Response - Step 4: live incident response playbook tests
# Horizon Valley Medical Center | Author: Sabitha S Karanavar
#
#   PB-03 ePHI storage threat : Microsoft Defender for Cloud built-in sample alerts (Storage)
#   PB-01 firewall change     : explicit Deny-Internet-inbound rule on the Data NSG (a hardening change, kept)
#   PB-02 privilege escalation: tabletop only (see the playbook) - no live change
# No test weakens any security control.
#
# COST: $0 - sample alerts, NSG rules, key rotation, alert e-mails and Sentinel incidents are free.
# Takes about 20-40 minutes (it waits for alerts and Sentinel incidents). Expect several alert e-mails.
set -uo pipefail
export PATH="$HOME/.azure-cli-env/bin:$PATH" PYTHONWARNINGS=ignore AZURE_CORE_ONLY_SHOW_ERRORS=true
HERE="$(cd "$(dirname "$0")" && pwd)"; mkdir -p "$HERE/../evidence/ir_tests"
python3 "$HERE/ir_tests.py" "$@" 2>&1 | tee -a "$HERE/../evidence/ir_tests/run_log.txt"
