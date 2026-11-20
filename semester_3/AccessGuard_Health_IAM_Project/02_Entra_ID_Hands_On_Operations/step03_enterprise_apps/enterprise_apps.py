"""
HVMC Healthcare IAM - Step 3: simulated enterprise applications in Microsoft Entra ID (Free tier, $0).

Horizon Valley Medical Center | Author: Sabitha S Karanavar

Creates one app registration + enterprise application (service principal) per HVMC business application, with
app roles for its access levels, "assignment required" ON, no client secrets or API permissions, and a homepage
on the reserved .example domain so it appears as a tile in My Apps.

Entra ID Free cannot assign GROUPS to apps (P1 feature), so access is assigned per USER, derived from the
SG-<Dept>-<App>-<Access> groups: the groups stay the single source of truth and this script keeps app
assignments in sync with them (adds missing, removes stale).

    python3 enterprise_apps.py            # DRY RUN
    python3 enterprise_apps.py --apply    # create/sync, then write evidence
"""
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(HERE, "evidence")
AZ = shutil.which("az") or os.path.expanduser("~/.azure-cli-env/bin/az")
G = "https://graph.microsoft.com/v1.0"
NS = uuid.UUID("6b2f0c1e-5d4a-4c8e-9a51-0f3c2b7e9d10")          # stable app-role ids

# app code (as used in group names) -> (display name, homepage host, roles)
APPS = {
    "EHR":            ("HVMC Electronic Health Record", "ehr", ["Read", "ReadWrite"]),
    "Pharmacy":       ("HVMC Pharmacy Management System", "pharmacy", ["Read", "ReadWrite"]),
    "LIS":            ("HVMC Laboratory Information System", "lis", ["Read", "ReadWrite"]),
    "HRPortal":       ("HVMC HR Portal", "hr", ["Read", "ReadWrite"]),
    "Payroll":        ("HVMC Payroll System", "payroll", ["ReadWrite"]),
    "FinanceERP":     ("HVMC Finance ERP", "erp", ["ReadWrite"]),
    "ITAdmin":        ("HVMC IT Administration Console", "itadmin", ["Limited", "Admin"]),
    "SecurityPortal": ("HVMC Security Monitoring Portal", "secportal", ["Admin"]),
    "Scheduling":     ("HVMC Appointment Scheduling", "scheduling", ["ReadWrite", "Admin"]),
    "VPN":            ("HVMC VPN Portal", "vpn", ["Read"]),
}
APP_ALIAS = {"PharmacySystem": "Pharmacy"}
# Legacy apps brought under group-driven sync (access review HVMC-AR-2026-Q4, decision "manage"):
# name -> (existing app role id to assign, groups whose members get it)
LEGACY = {"EHR-Simulated": ("18d14569-c3bd-439b-9a66-3a2aee01d14f", ["SG-Doctors-EHR-RW", "SG-Nursing-EHR-RW"])}


def name_of(code):
    return code[7:] if code.startswith("LEGACY:") else APPS[code][0]


def rid(code, role):
    return LEGACY[code[7:]][0] if code.startswith("LEGACY:") else role_id(code, role)
ROLE_ALIAS = {"RW": "ReadWrite"}
ROLE_DESC = {"Read": "View records only", "ReadWrite": "View and update records", "Admin": "Administer the application",
             "Limited": "Restricted, ticket-scoped access"}


def az(*args):
    env = dict(os.environ, PYTHONWARNINGS="ignore", AZURE_CORE_ONLY_SHOW_ERRORS="true")
    p = subprocess.run([AZ, *args], capture_output=True, text=True, env=env)
    if p.returncode:
        raise RuntimeError((p.stderr.strip().splitlines() or ["az failed"])[-1])
    return json.loads(p.stdout) if p.stdout.strip() else None


def graph(method, path, body=None):
    a = ["rest", "--method", method, "--url", G + path, "-o", "json"]
    if body is not None:
        a += ["--headers", "Content-Type=application/json", "--body", json.dumps(body)]
    return az(*a)


def role_id(app, role):
    return str(uuid.uuid5(NS, f"{app}:{role}"))


def desired_assignments(groups):
    """{(app, role): set(user ids)} from SG-<Dept>-<App>-<Access> group membership."""
    want = {}
    for g in groups:
        parts = g["displayName"].split("-")
        if len(parts) != 4:
            continue
        app, access = APP_ALIAS.get(parts[2], parts[2]), ROLE_ALIAS.get(parts[3], parts[3])
        if app not in APPS or access not in APPS[app][2]:
            continue
        members = graph("get", f"/groups/{g['id']}/members/microsoft.graph.user?$select=id,displayName,accountEnabled&$top=200")["value"]
        for m in members:
            if m["accountEnabled"]:
                want.setdefault((app, access), {})[m["id"]] = m["displayName"]
    return want


def main():
    apply = "--apply" in sys.argv
    groups = graph("get", "/groups?$filter=startswith(displayName,'SG-')&$select=id,displayName&$top=200")["value"]
    want = desired_assignments(groups)
    sps = {s["displayName"]: s for s in graph("get", "/servicePrincipals?$filter=startswith(displayName,'HVMC ')&$select=id,appId,displayName,appRoles,appRoleAssignmentRequired")["value"]}

    for lname in LEGACY:
        sps.update({x["displayName"]: x for x in graph("get", f"/servicePrincipals?$filter=displayName eq '{lname}'&$select=id,displayName")["value"]})
    plan_apps = [code for code, (name, _, _) in APPS.items() if name not in sps]
    plan_add, plan_remove = [], []
    for code, (name, _, roles) in APPS.items():
        current = {}
        if name in sps:
            for a in graph("get", f"/servicePrincipals/{sps[name]['id']}/appRoleAssignedTo?$top=999")["value"]:
                current[(a["principalId"], a["appRoleId"])] = a
        for role in roles:
            for uid, uname in want.get((code, role), {}).items():
                if (uid, role_id(code, role)) not in current:
                    plan_add.append((code, role, uid, uname))
        wanted_keys = {(uid, role_id(code, r)) for r in roles for uid in want.get((code, r), {})}
        for key, a in current.items():
            if key not in wanted_keys:
                plan_remove.append((code, a))

    gid = {g["displayName"]: g["id"] for g in groups}
    for lname, (lrole, lgroups) in LEGACY.items():
        if lname not in sps:
            continue
        code = "LEGACY:" + lname
        lwant = {}
        for gname in lgroups:
            for m in graph("get", f"/groups/{gid[gname]}/members/microsoft.graph.user?$select=id,displayName,accountEnabled&$top=200")["value"]:
                if m["accountEnabled"]:
                    lwant[m["id"]] = m["displayName"]
        current = {a["principalId"]: a for a in graph("get", f"/servicePrincipals/{sps[lname]['id']}/appRoleAssignedTo?$top=999")["value"]}
        plan_add += [(code, "User", uid, uname) for uid, uname in lwant.items() if uid not in current]
        plan_remove += [(code, a) for uid, a in current.items() if uid not in lwant]

    print(f"{'APPLY' if apply else 'DRY RUN'}\n\nEnterprise apps to create ({len(plan_apps)}):")
    for code in plan_apps:
        name, host, roles = APPS[code]
        print(f"  + {name:<38} roles: {', '.join(roles):<18} https://{host}.hvmc.example")
    print(f"\nUser assignments to add ({len(plan_add)}):")
    summary = {}
    for code, role, _, uname in plan_add:
        summary.setdefault(f"{name_of(code)} [{role}]", []).append(uname)
    for k, v in summary.items():
        print(f"  {k:<50} {len(v):>2}  {', '.join(sorted(v))}")
    print(f"\nStale assignments to remove ({len(plan_remove)}):")
    for code, a in plan_remove:
        print(f"  - {name_of(code)}: {a.get('principalDisplayName')}")
    if not apply:
        print("\nNothing was changed. Run with --apply to make these changes.")
        return

    os.makedirs(EVID, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    log = []

    def record(action, target, fn):
        try:
            fn()
            res, err = "ok", ""
        except Exception as e:
            res, err = "FAILED", str(e)
            print(f"  [FAILED] {action} {target}: {err}")
        log.append(dict(time=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), action=action, target=target,
                        result=res, error=err, ticket="HVMC-IAM-CHG-103"))

    for code in plan_apps:
        name, host, roles = APPS[code]
        def create(code=code, name=name, host=host, roles=roles):
            app = graph("post", "/applications", {
                "displayName": name, "signInAudience": "AzureADMyOrg",
                "web": {"homePageUrl": f"https://{host}.hvmc.example"},
                "tags": ["HVMC", "SimulatedApp", "HVMC-IAM-Lab"],
                "notes": "Simulated HVMC business application for IAM lab (no real backend, no credentials).",
                "appRoles": [{"id": role_id(code, r), "allowedMemberTypes": ["User"], "displayName": r, "value": f"{code}.{r}",
                              "description": ROLE_DESC[r], "isEnabled": True} for r in roles]})
            sps[name] = graph("post", "/servicePrincipals", {"appId": app["appId"], "appRoleAssignmentRequired": True,
                                                              "tags": ["WindowsAzureActiveDirectoryIntegratedApp", "HVMC-IAM-Lab"]})
        record("create app + enterprise app", name, create)
    for code, role, uid, uname in plan_add:
        sp = sps[name_of(code)]
        record("assign user", f"{name_of(code)} [{role}] <- {uname}",
               lambda sp=sp, uid=uid, code=code, role=role: graph("post", f"/servicePrincipals/{sp['id']}/appRoleAssignedTo",
                                                                  {"principalId": uid, "resourceId": sp["id"], "appRoleId": rid(code, role)}))
    for code, a in plan_remove:
        sp = sps[name_of(code)]
        record("remove stale assignment", f"{name_of(code)} - {a.get('principalDisplayName')}",
               lambda sp=sp, a=a: graph("delete", f"/servicePrincipals/{sp['id']}/appRoleAssignedTo/{a['id']}"))

    inventory = []
    for code, (name, host, roles) in APPS.items():
        sp = graph("get", f"/servicePrincipals?$filter=displayName eq '{name}'&$select=id,appId,appRoleAssignmentRequired")["value"]
        n = len(graph("get", f"/servicePrincipals/{sp[0]['id']}/appRoleAssignedTo?$top=999")["value"]) if sp else 0
        inventory.append(dict(app=name, roles=roles, assignmentRequired=sp[0]["appRoleAssignmentRequired"] if sp else None, assignedUsers=n))
    json.dump(dict(inventory=inventory, log=log), open(os.path.join(EVID, f"apps_{stamp}.json"), "w"), indent=1)
    print(f"\n{sum(l['result'] == 'ok' for l in log)}/{len(log)} changes applied.")
    for i in inventory:
        print(f"  {i['app']:<38} assignment required={i['assignmentRequired']}  users={i['assignedUsers']}")


if __name__ == "__main__":
    main()
