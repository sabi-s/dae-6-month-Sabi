"""
HVMC Healthcare IAM - Step 6: deploy the Conditional Access policies (report-only) once the tenant is licensed.

    python3 deploy_ca.py            # DRY RUN: licence check, placeholders, policies to create
    python3 deploy_ca.py --apply    # only works with Entra ID P1/P2 (e.g. the free 30-day P2 trial)

Deployment order (refused without a licence):
  1. create 2 cloud-only break-glass accounts (FIDO2) and group SG-CA-Exclude-BreakGlass  [manual, documented]
  2. create named location NL-Allowed-Countries-US
  3. create every policy in report-only state; review sign-in logs / What-If for 14 days
  4. switch policies to "enabled" ring by ring (IT pilot -> clinical -> everyone), then turn security defaults OFF
"""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "step2_rbac_v2"))
from rbac_v2 import graph          # noqa: E402

CA_SKUS = ("AAD_PREMIUM", "AAD_PREMIUM_P2", "ENTERPRISEPREMIUM", "SPE_E3", "SPE_E5", "EMS", "EMSPREMIUM", "M365_BUSINESS_PREMIUM", "SPB",
           "Microsoft_Entra_ID_P1", "Microsoft_Entra_ID_P2")


def main():
    skus = [s["skuPartNumber"] for s in graph("get", "/subscribedSkus")["value"]]
    licensed = any(any(k.lower() in s.lower() for k in CA_SKUS) for s in skus)
    files = sorted(glob.glob(os.path.join(HERE, "policies", "*.json")))
    print(f"Tenant licences: {skus or 'none (Entra ID Free)'} -> Conditional Access {'AVAILABLE' if licensed else 'NOT available'}\n")
    for f in files:
        p = json.load(open(f))
        holders = sorted({h for h in json.dumps(p).split('"') if h.startswith("{{")})
        print(f"  {p['displayName']:<62} state={p['state']}  placeholders={','.join(holders) or '-'}")
    if "--apply" not in sys.argv:
        print("\nDRY RUN - nothing created.")
        return
    if not licensed:
        raise SystemExit("\nRefused: Conditional Access needs Entra ID P1/P2. Start the free P2 trial, then re-run.")
    raise SystemExit("\nLicensed: complete the manual break-glass and named-location steps first (see docstring), "
                     "then fill the placeholders and POST each file to /identity/conditionalAccess/policies.")


if __name__ == "__main__":
    main()
