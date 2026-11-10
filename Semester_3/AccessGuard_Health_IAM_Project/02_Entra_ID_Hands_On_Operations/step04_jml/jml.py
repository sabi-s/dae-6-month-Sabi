"""
HVMC Healthcare IAM - Step 4: Joiner / Mover / Leaver in Microsoft Entra ID (Free tier, $0).

Horizon Valley Medical Center | Author: Sabitha S Karanavar

Group membership is DERIVED from the RBAC v2 matrix (step2_rbac_v2/rbac_v2.py), and app access is then
synced from groups by step3_enterprise_apps/enterprise_apps.py - so access always follows the design.

    python3 jml.py joiner   [--apply]   # HVMC-JML-201: new Registered Nurse
    python3 jml.py mover    [--apply]   # HVMC-JML-202: Nursing -> Pharmacy transfer
    python3 jml.py leaver   [--apply]   # HVMC-JML-203: contractor early termination

Without --apply nothing is changed. The new joiner's initial password is random, never printed or stored;
the account is handed over through a helpdesk password reset (forced change at first sign-in).
"""
import datetime as dt
import json
import os
import secrets
import string
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "step2_rbac_v2"))
from rbac_v2 import MATRIX, group_name, graph, G          # noqa: E402

EVID = os.path.join(HERE, "evidence")
DOMAIN = "sabithaskaranavargmail.onmicrosoft.com"

CASES = {
    "joiner": dict(ticket="HVMC-JML-201", summary="New hire: Olivia Bennett, Registered Nurse, starts 2026-10-21",
                   user=dict(given="Olivia", sur="Bennett", dept="Nursing", title="Registered Nurse",
                             manager="Angela Brooks", employeeId="HVMC-1108", hire="2026-10-21T00:00:00Z")),
    "mover":  dict(ticket="HVMC-JML-202", summary="Transfer: Noah Fischer, Nursing -> Pharmacy as Pharmacy Technician",
                   user=dict(name="Noah Fischer", dept="Pharmacy", title="Pharmacy Technician", manager="David Patel")),
    "leaver": dict(ticket="HVMC-JML-203", summary="Termination: contractor Carlos Diaz, engagement ended early (sponsor Kevin O'Brien)",
                   user=dict(name="Carlos Diaz")),
}


def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def find_user(name):
    sel = "id,displayName,userPrincipalName,department,jobTitle,accountEnabled,employeeId,employeeType,employeeHireDate,employeeLeaveDateTime"
    r = graph("get", f"/users?$filter=displayName eq '{name.replace(chr(39), chr(39) * 2)}'&$select={sel}&$expand=manager($select=displayName)")["value"]
    return r[0] if r else None


def sg_groups():
    return {g["displayName"]: g for g in graph("get", "/groups?$filter=startswith(displayName,'SG-')&$select=id,displayName&$top=200")["value"]}


def member_of(uid):
    return {g["displayName"] for g in graph("get", f"/users/{uid}/memberOf/microsoft.graph.group?$select=displayName&$top=200")["value"]
            if g["displayName"].startswith("SG-")}


def apps_of(uid):
    return sorted(f"{a['resourceDisplayName']}" for a in graph("get", f"/users/{uid}/appRoleAssignments?$top=200")["value"])


def snapshot(name):
    u = find_user(name)
    if not u:
        return None
    return dict(user=u, groups=sorted(member_of(u["id"])), apps=apps_of(u["id"]))


def desired(dept):
    return {group_name(dept, a, x) for a, x in MATRIX[dept].items()}


def sync_apps():
    p = subprocess.run([sys.executable, os.path.join(ROOT, "step3_enterprise_apps", "enterprise_apps.py"), "--apply"],
                       capture_output=True, text=True, env=dict(os.environ))
    lines = [l for l in p.stdout.splitlines() if "applied" in l or "FAILED" in l]
    return lines[-1] if lines else p.stderr.strip()[-200:]


def plan(kind):
    c = CASES[kind]["user"]
    steps = []                               # (description, fn) ; fn executed only with --apply
    groups = sg_groups()
    if kind == "joiner":
        name = f"{c['given']} {c['sur']}"
        if find_user(name):
            raise SystemExit(f"{name} already exists - joiner already processed")
        upn = f"{c['given'].lower()}.{c['sur'].lower()}@{DOMAIN}"
        mgr = find_user(c["manager"])
        state = {}

        def create():
            pwd = "".join(secrets.choice(string.ascii_letters + string.digits + "!@#%^*-_") for _ in range(24))
            state["u"] = graph("post", "/users", {
                "accountEnabled": True, "displayName": name, "givenName": c["given"], "surname": c["sur"],
                "mailNickname": f"{c['given'].lower()}.{c['sur'].lower()}", "userPrincipalName": upn,
                "department": c["dept"], "jobTitle": c["title"], "employeeId": c["employeeId"], "employeeType": "Employee",
                "employeeHireDate": c["hire"], "companyName": "Horizon Valley Medical Center", "usageLocation": "US",
                "passwordProfile": {"forceChangePasswordNextSignIn": True, "password": pwd}})
        steps.append((f"create account {upn} (dept {c['dept']}, {c['title']}, {c['employeeId']}, hire {c['hire'][:10]}, "
                      "random initial password, change forced at first sign-in)", create))
        steps.append((f"set manager -> {c['manager']}",
                      lambda: graph("put", f"/users/{state['u']['id']}/manager/$ref", {"@odata.id": f"{G}/users/{mgr['id']}"})))
        for g in sorted(desired(c["dept"])):
            steps.append((f"add to {g}", lambda g=g: graph("post", f"/groups/{groups[g]['id']}/members/$ref",
                                                            {"@odata.id": f"{G}/directoryObjects/{state['u']['id']}"})))
        return name, steps

    u = find_user(c["name"])
    if not u:
        raise SystemExit(f"user not found: {c['name']}")
    current = member_of(u["id"])

    if kind == "mover":
        mgr = find_user(c["manager"])
        target = desired(c["dept"])
        steps.append((f"department {u['department']} -> {c['dept']}; title {u['jobTitle']} -> {c['title']} "
                      f"(employee ID {u['employeeId']} kept - IDs follow the person, not the job)",
                      lambda: graph("patch", f"/users/{u['id']}", {"department": c["dept"], "jobTitle": c["title"]})))
        steps.append((f"manager {(u.get('manager') or {}).get('displayName')} -> {c['manager']}",
                      lambda: graph("put", f"/users/{u['id']}/manager/$ref", {"@odata.id": f"{G}/users/{mgr['id']}"})))
        for g in sorted(current - target):
            steps.append((f"REMOVE from {g} (old role)", lambda g=g: graph("delete", f"/groups/{groups[g]['id']}/members/{u['id']}/$ref")))
        for g in sorted(target - current):
            steps.append((f"add to {g} (new role)", lambda g=g: graph("post", f"/groups/{groups[g]['id']}/members/$ref",
                                                                       {"@odata.id": f"{G}/directoryObjects/{u['id']}"})))
        return c["name"], steps

    # leaver
    steps.append(("disable sign-in (accountEnabled -> false)", lambda: graph("patch", f"/users/{u['id']}", {"accountEnabled": False})))
    steps.append(("revoke all refresh tokens / sign-in sessions", lambda: graph("post", f"/users/{u['id']}/revokeSignInSessions", {})))
    steps.append((f"record leave date -> {now()[:10]}", lambda: graph("patch", f"/users/{u['id']}", {"employeeLeaveDateTime": now()})))
    for g in sorted(current):
        steps.append((f"REMOVE from {g}", lambda g=g: graph("delete", f"/groups/{groups[g]['id']}/members/{u['id']}/$ref")))
    return c["name"], steps


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in CASES:
        raise SystemExit(__doc__)
    kind, apply = sys.argv[1], "--apply" in sys.argv
    case = CASES[kind]
    name, steps = plan(kind)
    print(f"{'APPLY' if apply else 'DRY RUN'} {case['ticket']} {kind.upper()}: {case['summary']}\n")
    for i, (d, _) in enumerate(steps, 1):
        print(f"  {i:>2}. {d}")
    print(f"  {len(steps) + 1:>2}. sync enterprise-app access from groups (step 3 script)")
    if not apply:
        print("\nNothing was changed. Run with --apply to make these changes.")
        return
    os.makedirs(EVID, exist_ok=True)
    before = snapshot(name)
    log = []
    for d, fn in steps:
        try:
            fn()
            res, err = "ok", ""
        except Exception as e:
            res, err = "FAILED", str(e)
            print(f"  [FAILED] {d}: {err}")
        log.append(dict(time=now(), step=d, result=res, error=err))
    log.append(dict(time=now(), step="sync enterprise-app access", result=sync_apps(), error=""))
    after = snapshot(name)
    record = dict(ticket=case["ticket"], type=kind, summary=case["summary"], executed_by="Sabitha S Karanavar (IAM administrator)",
                  started=log[0]["time"], finished=now(), before=before, after=after, steps=log)
    path = os.path.join(EVID, f"{case['ticket']}_{kind}.json")
    json.dump(record, open(path, "w"), indent=1, default=str)
    print(f"\n{sum(l['result'] == 'ok' for l in log[:-1])}/{len(log) - 1} steps ok; app sync: {log[-1]['result']}")
    print(f"before: groups={len((before or {}).get('groups', []))} apps={len((before or {}).get('apps', []))}  ->  "
          f"after: enabled={after['user']['accountEnabled']} groups={len(after['groups'])} apps={len(after['apps'])}")
    print(f"evidence: {path}")


if __name__ == "__main__":
    main()
