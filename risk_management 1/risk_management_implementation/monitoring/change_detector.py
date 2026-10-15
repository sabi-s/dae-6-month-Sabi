"""
HVMC environmental change detection — read-only.

Horizon Valley Medical Center (HVMC) - Risk Management Implementation
Author: Sabitha S Karanavar

Takes a snapshot of the HVMC Azure subscription and Entra ID tenant (read-only
Azure CLI / Microsoft Graph queries), compares it with the previous snapshot, and
classifies every difference by severity. Each change names the risks to re-assess
and the integration procedure that should have authorised it (change management,
joiner-mover-leaver, etc.). Optionally checks the CISA Known Exploited
Vulnerabilities (KEV) catalogue for products in the HVMC software inventory.

    python3 change_detector.py              # snapshot + diff vs previous; exit 2 if High/Critical change
    python3 change_detector.py --threat-feed
"""
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SNAP_DIR = os.path.join(HERE, "snapshots")
AZ = shutil.which("az") or os.path.expanduser("~/.azure-cli-env/bin/az")
RG, STORAGE = "HVMC-CloudSecurity-RG", "hvmcehrstorage"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
INVENTORY = {  # product keywords from the HVMC asset inventory -> risk to re-assess
    "openssh": "R09", "apache http server": "R10", "azure": "R02", "entra": "R04", "samba": "DC (planned)",
}
SEV_ORDER = ["Info", "Low", "Medium", "High", "Critical"]


def az(*args):
    env = dict(os.environ, PYTHONWARNINGS="ignore")
    out = subprocess.run([AZ, *args, "-o", "json"], capture_output=True, text=True, env=env)
    if out.returncode:
        raise RuntimeError(f"az {' '.join(args[:3])}: " + (out.stderr.strip().splitlines() or ["failed"])[-1])
    return json.loads(out.stdout or "null")


# ------------------------------------------------------------ snapshot
def snapshot():
    s = {}
    s["resources"] = sorted(f'{r["type"]}|{r["name"]}' for r in az("resource", "list"))
    rules = {}
    for nsg in az("network", "nsg", "list"):
        for r in nsg.get("securityRules", []):
            src = r.get("sourceAddressPrefix") or ",".join(r.get("sourceAddressPrefixes") or [])
            port = r.get("destinationPortRange") or ",".join(r.get("destinationPortRanges") or [])
            rules[f'{nsg["name"]}/{r["name"]}'] = f'{r["direction"]} {r["access"]} {r["protocol"]} {src} -> {port} p{r["priority"]}'
    s["nsg_rules"] = rules
    s["role_assignments"] = sorted(f'{a.get("principalName") or a["principalId"]}|{a["roleDefinitionName"]}|{a["scope"].split("/")[-1]}'
                                   for a in az("role", "assignment", "list", "--all"))
    roles = az("rest", "--method", "get", "--url", "https://graph.microsoft.com/v1.0/directoryRoles?$expand=members($select=userPrincipalName)")["value"]
    s["directory_roles"] = {r["displayName"]: sorted(m.get("userPrincipalName") or m["id"] for m in r["members"]) for r in roles}
    s["users"] = sorted(u["userPrincipalName"] for u in az("ad", "user", "list"))
    groups = {}
    for g in az("ad", "group", "list", "--query", "[?starts_with(displayName,'SG-')].displayName"):
        groups[g] = sorted(m["displayName"] for m in az("ad", "group", "member", "list", "--group", g))
    s["group_members"] = groups
    st = az("storage", "account", "show", "-n", STORAGE, "-g", RG)
    s["storage_security"] = {"publicNetworkAccess": st.get("publicNetworkAccess"), "defaultAction": (st.get("networkRuleSet") or {}).get("defaultAction"),
                             "allowSharedKeyAccess": st.get("allowSharedKeyAccess"), "allowBlobPublicAccess": st.get("allowBlobPublicAccess"),
                             "minimumTlsVersion": st.get("minimumTlsVersion"), "enableHttpsTrafficOnly": st.get("enableHttpsTrafficOnly")}
    s["public_ips"] = sorted(f'{p["name"]}|{p.get("ipAddress")}' for p in az("network", "public-ip", "list"))
    pol = az("rest", "--method", "get", "--url", "https://graph.microsoft.com/v1.0/policies/authorizationPolicy")
    s["tenant_policy"] = {"allowInvitesFrom": pol["allowInvitesFrom"], **{k: v for k, v in pol["defaultUserRolePermissions"].items()
                                                                          if k.startswith("allowedTo")}}
    return s


# ------------------------------------------------------------ diff + classification
RULES = {  # category -> (severity for add, remove, change), risks, procedure
    "resources": (("Medium", "Low", "Low"), "R01, R15", "IP-1 Change management: new resource must be categorised (RMF Step 2) before go-live"),
    "nsg_rules": (("Medium", "Medium", "Medium"), "R03", "IP-1 Change management: firewall/NSG change needs an approved ticket"),
    "role_assignments": (("Medium", "Low", "Medium"), "R04, R07", "IP-2 Access governance: privileged access needs approval"),
    "directory_roles": (("High", "Medium", "High"), "R04", "IP-2 Access governance: directory role change needs Security & Risk Lead approval"),
    "users": (("Low", "Low", "Low"), "R06, R07", "IP-3 Joiner-mover-leaver: account must match an HR/contract record"),
    "group_members": (("Medium", "Low", "Medium"), "R13", "IP-3 Joiner-mover-leaver: access change must match an approved request"),
    "storage_security": (("High", "High", "High"), "R02, R05", "IP-1 Change management: ePHI store configuration change"),
    "public_ips": (("High", "Low", "High"), "R03, R10", "IP-1 Change management: new internet exposure requires risk assessment"),
    "tenant_policy": (("Medium", "Medium", "Medium"), "R08", "IP-2 Access governance: tenant-wide setting change"),
}
SECURE = {"publicNetworkAccess": "Disabled", "defaultAction": "Deny", "allowSharedKeyAccess": False, "allowBlobPublicAccess": False,
          "minimumTlsVersion": "TLS1_2", "enableHttpsTrafficOnly": True}


def escalate(cat, kind, key, old, new):
    sev = RULES[cat][0][["added", "removed", "changed"].index(kind)]
    text = f"{key}: {old} -> {new}" if kind == "changed" else str(key)
    if cat == "nsg_rules" and new and ("Inbound Allow" in str(new)) and any(s in str(new) for s in (" * ", "Internet", "0.0.0.0/0")):
        sev = "High"                                             # new internet-facing allow rule
    if cat == "role_assignments" and kind == "added" and any(r in str(key) for r in ("|Owner|", "|Contributor|", "|User Access Administrator|")):
        sev = "High"
    if cat == "directory_roles" and "Global Administrator" in str(key) and kind in ("added", "changed"):
        sev = "Critical"
    if cat == "storage_security":
        sev = "Info" if new == SECURE.get(key) else "High"     # moved toward secure = good news
    return sev, text


def diff(old, new):
    changes = []
    for cat in RULES:
        o, n = old.get(cat), new.get(cat)
        if isinstance(n, list):
            for x in sorted(set(n) - set(o or [])):
                changes.append(("added", cat, x, None, x))
            for x in sorted(set(o or []) - set(n)):
                changes.append(("removed", cat, x, x, None))
        elif isinstance(n, dict):
            for k in sorted(set(n) | set(o or {})):
                ov, nv = (o or {}).get(k), n.get(k)
                if ov == nv:
                    continue
                if isinstance(nv, list) or isinstance(ov, list):          # e.g. group or role membership
                    for m in sorted(set(nv or []) - set(ov or [])):
                        changes.append(("added", cat, f"{k} += {m}", None, m))
                    for m in sorted(set(ov or []) - set(nv or [])):
                        changes.append(("removed", cat, f"{k} -= {m}", m, None))
                else:
                    kind = "added" if ov is None else "removed" if nv is None else "changed"
                    changes.append((kind, cat, k, ov, nv))
    out = []
    for kind, cat, key, ov, nv in changes:
        sev, text = escalate(cat, kind, key if cat != "directory_roles" else key, ov, nv)
        if cat == "directory_roles" and "Global Administrator" in key and kind == "added":
            sev = "Critical"
        out.append(dict(category=cat, kind=kind, detail=text, severity=sev, reassess=RULES[cat][1], procedure=RULES[cat][2]))
    return sorted(out, key=lambda c: -SEV_ORDER.index(c["severity"]))


def threat_feed():
    try:
        with urllib.request.urlopen(KEV_URL, timeout=20) as r:
            kev = json.load(r)
    except Exception as e:
        return dict(ok=False, error=str(e))
    since = (dt.date.today() - dt.timedelta(days=30)).isoformat()
    hits = []
    for v in kev.get("vulnerabilities", []):
        prod = f'{v.get("vendorProject", "")} {v.get("product", "")}'.lower()
        for kw, risk in INVENTORY.items():
            if kw in prod and v.get("dateAdded", "") >= since:
                hits.append(dict(cve=v["cveID"], product=f'{v["vendorProject"]} {v["product"]}', added=v["dateAdded"], reassess=risk,
                                 name=v.get("vulnerabilityName", "")))
    return dict(ok=True, catalog_version=kev.get("catalogVersion"), total=len(kev.get("vulnerabilities", [])), window_days=30, hits=hits)


def main():
    os.makedirs(SNAP_DIR, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    snaps = sorted(f for f in os.listdir(SNAP_DIR) if f.endswith(".json"))
    new = snapshot()
    with open(os.path.join(SNAP_DIR, f"{now}.json"), "w") as f:
        json.dump(new, f, indent=1)
    if snaps:
        with open(os.path.join(SNAP_DIR, snaps[-1])) as f:
            old = json.load(f)
        changes, baseline = diff(old, new), snaps[-1]
    else:
        changes, baseline = [], None
    report = dict(run=now, baseline=baseline, first_run=baseline is None, changes=changes,
                  counts={s: sum(c["severity"] == s for c in changes) for s in SEV_ORDER},
                  inventory={k: len(v) for k, v in new.items()})
    if "--threat-feed" in sys.argv:
        report["threat_feed"] = threat_feed()
    with open(os.path.join(HERE, "change_report.json"), "w") as f:
        json.dump(report, f, indent=2)
    print(f"snapshot {now}; baseline {baseline or '(none — this run is the baseline)'}")
    print("inventory:", report["inventory"])
    for c in changes:
        print(f"[{c['severity']}] {c['category']} {c['kind']}: {c['detail']}  -> re-assess {c['reassess']}")
    if "threat_feed" in report:
        tf = report["threat_feed"]
        print("threat feed:", f"{tf['total']} KEV entries, {len(tf['hits'])} new for HVMC inventory in 30 days" if tf["ok"] else tf["error"])
    sys.exit(2 if report["counts"]["High"] or report["counts"]["Critical"] else 0)


if __name__ == "__main__":
    main()
