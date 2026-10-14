"""
HVMC Key Risk Indicator (KRI) monitor — read-only.

Horizon Valley Medical Center (HVMC) - Risk Communication
Author: Sabitha S Karanavar

Queries the HVMC Azure subscription and Entra ID tenant with read-only Azure CLI
commands, evaluates each KRI against its Green / Amber / Red thresholds, and writes
kri_status.json, which the risk dashboard reads. Any Red KRI is an alert.

Run on a schedule (e.g. daily via cron, Azure Automation or a CI pipeline):
    python3 kri_monitor.py                # writes kri_status.json, exit 2 if any Red
Requires: Azure CLI logged in with Reader + Directory Reader access.
"""
import datetime as dt
import json
import os
import shutil
import subprocess
import sys

RG, STORAGE, DATA_NSG = "HVMC-CloudSecurity-RG", "hvmcehrstorage", "HVMC-Data-NSG"
AZ = shutil.which("az") or os.path.expanduser("~/.azure-cli-env/bin/az")


def az(*args):
    env = dict(os.environ, PYTHONWARNINGS="ignore")
    out = subprocess.run([AZ, *args, "-o", "json"], capture_output=True, text=True, env=env)
    if out.returncode:
        raise RuntimeError(out.stderr.strip().splitlines()[-1] if out.stderr.strip() else "az failed")
    return json.loads(out.stdout or "null")


def kri(kid, name, risk, control, value, status, target, source):
    return dict(id=kid, name=name, risk=risk, control=control, value=value, status=status, target=target, source=source)


def collect():
    res = []
    st = az("storage", "account", "show", "-n", STORAGE, "-g", RG)
    res.append(kri("K01", "EHR storage public network access", "R02", "C02", st.get("publicNetworkAccess"),
                   "Red" if st.get("publicNetworkAccess") != "Disabled" else "Green", "Disabled", "az storage account show"))
    res.append(kri("K02", "EHR storage shared-key access", "R02", "C02", st.get("allowSharedKeyAccess"),
                   "Amber" if st.get("allowSharedKeyAccess") is not False else "Green", "false", "az storage account show"))
    bs = az("storage", "account", "blob-service-properties", "show", "-n", STORAGE, "-g", RG)
    ver = bool(bs.get("isVersioningEnabled"))
    days = (bs.get("deleteRetentionPolicy") or {}).get("days") or 0
    res.append(kri("K03", "EHR blob versioning", "R05", "C05", "Enabled" if ver else "Disabled", "Green" if ver else "Red", "Enabled",
                   "blob-service-properties"))
    res.append(kri("K04", "Blob soft-delete retention (days)", "R05", "C05", days, "Green" if days >= 30 else "Amber" if days >= 7 else "Red", "≥ 30",
                   "blob-service-properties"))
    rules = az("network", "nsg", "rule", "list", "-g", RG, "--nsg-name", DATA_NSG)
    deny = any(r["access"] == "Deny" and r["direction"] == "Inbound" for r in rules)
    res.append(kri("K05", "Data-tier explicit deny rule", "R03", "C03", "Present" if deny else "Missing", "Green" if deny else "Red", "Present",
                   "az network nsg rule list"))
    roles = az("rest", "--method", "get", "--url",
               "https://graph.microsoft.com/v1.0/directoryRoles?$expand=members($select=displayName)")["value"]
    ga = next((len(r["members"]) for r in roles if r["displayName"] == "Global Administrator"), 0)
    res.append(kri("K06", "Global Administrators", "R04", "C04", ga, "Red" if ga < 2 else "Amber" if ga > 4 else "Green", "2–4 incl. break-glass",
                   "Graph directoryRoles"))
    sub = az("account", "show")["id"]
    diag = az("monitor", "diagnostic-settings", "subscription", "list", "--subscription", sub)
    n_diag = len(diag.get("value", diag) if isinstance(diag, dict) else diag)
    res.append(kri("K07", "Activity log exported to Log Analytics", "R01", "C01", n_diag, "Green" if n_diag else "Red", "≥ 1",
                   "az monitor diagnostic-settings subscription list"))
    alerts = az("monitor", "activity-log", "alert", "list")
    res.append(kri("K08", "Activity-log alert rules", "R01", "C01", len(alerts), "Green" if len(alerts) >= 3 else "Amber" if alerts else "Red", "≥ 3",
                   "az monitor activity-log alert list"))
    flows = az("network", "watcher", "flow-log", "list", "-l", "eastus")
    res.append(kri("K09", "Network flow logs", "R01", "C01", len(flows), "Green" if flows else "Amber", "≥ 1", "az network watcher flow-log list"))
    pricing = az("security", "pricing", "show", "-n", "StorageAccounts")
    tier = pricing.get("pricingTier")
    res.append(kri("K10", "Defender for Storage", "R11", "C06", tier, "Green" if tier == "Standard" else "Amber", "Standard",
                   "az security pricing show"))
    contacts = az("security", "contact", "list")
    res.append(kri("K11", "Security alert contacts", "R11", "C06", len(contacts), "Green" if contacts else "Amber", "≥ 1", "az security contact list"))
    pol = az("rest", "--method", "get", "--url", "https://graph.microsoft.com/v1.0/policies/authorizationPolicy")
    apps = pol["defaultUserRolePermissions"]["allowedToCreateApps"]
    invites = pol["allowInvitesFrom"]
    res.append(kri("K12", "Users can register applications", "R08", "C08", apps, "Amber" if apps else "Green", "false", "Graph authorizationPolicy"))
    res.append(kri("K13", "Guest invitations allowed from", "R08", "C08", invites, "Amber" if invites == "everyone" else "Green", "adminsAndGuestInviters",
                   "Graph authorizationPolicy"))
    users = az("ad", "user", "list", "--query", "[].displayName")
    tests = [u for u in users if "test" in u.lower()]
    res.append(kri("K14", "Test/shared accounts in production", "R07", "C14", len(tests), "Amber" if tests else "Green", "0", "az ad user list"))
    locks = az("lock", "list", "-g", RG)
    res.append(kri("K15", "Resource locks on production RG", "R15", "A01", len(locks), "Green" if locks else "Amber", "≥ 1 (accepted risk)",
                   "az lock list"))
    return res


def main():
    started = dt.datetime.now(dt.timezone.utc)
    try:
        kris = collect()
        error = None
    except Exception as e:                       # report, don't crash the scheduler
        kris, error = [], str(e)
    out = dict(generated=started.strftime("%Y-%m-%dT%H:%M:%SZ"), subscription="Azure subscription 1", error=error, kris=kris,
               summary={s: sum(k["status"] == s for k in kris) for s in ("Red", "Amber", "Green")})
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kri_status.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    for k in kris:
        print(f"{k['id']} {k['status']:<5} {k['name']}: {k['value']} (target {k['target']})")
    print("summary:", out["summary"], "| error:" if error else "", error or "")
    sys.exit(2 if out["summary"].get("Red") or error else 0)


if __name__ == "__main__":
    main()
