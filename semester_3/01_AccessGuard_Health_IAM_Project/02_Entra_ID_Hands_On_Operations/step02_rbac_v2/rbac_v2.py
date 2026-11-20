"""
HVMC Healthcare IAM - Step 2: RBAC v2 in Microsoft Entra ID (Free tier, $0).

Horizon Valley Medical Center | Author: Sabitha S Karanavar

The Day 2 RBAC matrix gives most roles access to more than one application, but only one group per
department existed. RBAC v2 adds one security group per (department, application, access level) so that
group membership grants exactly the matrix - no more, no less - and checks coverage user by user.

    python3 rbac_v2.py            # DRY RUN: coverage before, groups/memberships to add; changes nothing
    python3 rbac_v2.py --apply    # creates groups, adds members, re-checks coverage, writes evidence
"""
import datetime as dt
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(HERE, "evidence")
AZ = shutil.which("az") or os.path.expanduser("~/.azure-cli-env/bin/az")
G = "https://graph.microsoft.com/v1.0"

APPS = {"EHR": "Electronic Health Record", "Pharmacy": "Pharmacy Management System", "PharmacySystem": "Pharmacy Management System",
        "LIS": "Laboratory Information System", "Payroll": "Payroll System", "HRPortal": "HR Portal", "FinanceERP": "Finance ERP",
        "ITAdmin": "IT Administration Console", "SecurityPortal": "Security Monitoring Portal", "Scheduling": "Appointment Scheduling",
        "VPN": "VPN Portal"}

# Day 2 RBAC matrix (role = department) -> {application: access}; VPN from the Day 2 application list
MATRIX = {
    "Doctors":         {"EHR": "RW", "Pharmacy": "Read", "LIS": "Read"},
    "Nursing":         {"EHR": "RW", "Pharmacy": "Read", "LIS": "Read"},
    "Pharmacy":        {"EHR": "Read", "PharmacySystem": "RW"},
    "Laboratory":      {"EHR": "Read", "LIS": "RW"},
    "Human Resources": {"Payroll": "RW", "HRPortal": "RW"},
    "Finance":         {"Payroll": "RW", "HRPortal": "Read", "FinanceERP": "RW"},
    "IT":              {"ITAdmin": "Admin", "Scheduling": "Admin", "VPN": "Read"},   # RBAC v2 decisions D1, D2 below
    "Security":        {"SecurityPortal": "Admin"},
    "Reception":       {"EHR": "Read", "Scheduling": "RW"},
    "Contractors":     {"ITAdmin": "Limited", "VPN": "Read"},
}
PREFIX = {"Doctors": "Doctors", "Nursing": "Nursing", "Pharmacy": "Pharmacy", "Laboratory": "Lab", "Human Resources": "HR",
          "Finance": "Finance", "IT": "IT", "Security": "Security", "Reception": "Reception", "Contractors": "Contractors"}
# Matrix entries deliberately NOT provisioned, with the reason (recorded in the evidence)
HELD = {
    ("Contractors", "EHR", "Limited"): "No Business Associate Agreement on file for the contractor (risk R06) - ePHI access held until signed.",
    # RBAC v2 design decisions approved 2026-10-20 (change HVMC-IAM-CHG-102)
    ("IT", "EHR", "Read"): "D1 least privilege / HIPAA minimum necessary: IT staff get no standing ePHI access; break-fix access to be just-in-time.",
    ("IT", "Pharmacy", "Read"): "D1 least privilege / HIPAA minimum necessary: no standing ePHI access for IT.",
    ("IT", "LIS", "Read"): "D1 least privilege / HIPAA minimum necessary: no standing ePHI access for IT.",
    ("IT", "SecurityPortal", "Admin"): "D2 separation of duties: only the Security team administers security monitoring of IT's own actions.",
}
DESC_FIX = {"SG-Reception-Scheduling-RW": "Reception staff - Appointment Scheduling read/write"}


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


def group_name(dept, app, access):
    return f"SG-{PREFIX[dept]}-{app}-{access}"


def state():
    users = graph("get", "/users?$select=id,displayName,department,accountEnabled&$top=200")["value"]
    groups = graph("get", "/groups?$filter=startswith(displayName,'SG-')&$select=id,displayName,description&$top=200")["value"]
    members = {g["displayName"]: {m["id"] for m in graph("get", f"/groups/{g['id']}/members?$select=id&$top=200")["value"]}
               for g in groups}
    return users, {g["displayName"]: g for g in groups}, members


def coverage(users, members):
    """Per user: matrix entitlements missing, and group access not in the matrix."""
    rows = []
    for u in users:
        dept = u.get("department")
        if dept not in MATRIX or not u["accountEnabled"]:
            continue
        want = {group_name(dept, a, x) for a, x in MATRIX[dept].items()}
        have = {g for g, m in members.items() if u["id"] in m}
        rows.append(dict(user=u["displayName"], department=dept, missing=sorted(want - have), extra=sorted(have - want)))
    return rows


def main():
    apply = "--apply" in sys.argv
    users, groups, members = state()
    before = coverage(users, members)
    gaps = sum(len(r["missing"]) for r in before)
    print(f"{'APPLY' if apply else 'DRY RUN'} - coverage BEFORE: {sum(not r['missing'] for r in before)}/{len(before)} users fully match "
          f"the RBAC matrix; {gaps} missing entitlement(s); {sum(len(r['extra']) for r in before)} extra\n")

    new_groups, adds = [], []
    for dept, apps in MATRIX.items():
        dept_users = [u for u in users if u.get("department") == dept and u["accountEnabled"]]
        for app, access in apps.items():
            name = group_name(dept, app, access)
            if name not in groups:
                new_groups.append((name, f"{dept} - {APPS[app]} {access.lower()}"))
            for u in dept_users:
                if u["id"] not in members.get(name, set()):
                    adds.append((name, u))
    fixes = [(n, d) for n, d in DESC_FIX.items() if n in groups and groups[n].get("description") != d]

    print(f"Groups to create ({len(new_groups)}):")
    for n, d in new_groups:
        print(f"  + {n:<34} {d}")
    print(f"\nMemberships to add ({len(adds)}):")
    by_group = {}
    for n, u in adds:
        by_group.setdefault(n, []).append(u["displayName"])
    for n, names in by_group.items():
        print(f"  {n:<34} <- {', '.join(names)}")
    for n, d in fixes:
        print(f"\nDescription fix: {n}: '{groups[n].get('description')}' -> '{d}'")
    for (dept, app, access), why in HELD.items():
        print(f"\nHELD (not provisioned): {group_name(dept, app, access)} - {why}")
    if not apply:
        print("\nNothing was changed. Run with --apply to make these changes.")
        return

    os.makedirs(EVID, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    log = []

    def record(action, target, fn):
        try:
            fn()
            ok, err = "ok", ""
        except Exception as e:
            ok, err = "FAILED", str(e)
        log.append(dict(time=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), action=action, target=target,
                        result=ok, error=err, ticket="HVMC-IAM-CHG-102"))
        if ok != "ok":
            print(f"  [FAILED] {action} {target}: {err}")

    for n, d in new_groups:
        def create(n=n, d=d):
            groups[n] = graph("post", "/groups", {"displayName": n, "description": d, "securityEnabled": True,
                                                   "mailEnabled": False, "mailNickname": n.replace("-", "").lower()})
        record("create group", n, create)
    for n, u in adds:
        record("add member", f"{n} <- {u['displayName']}",
               lambda n=n, u=u: graph("post", f"/groups/{groups[n]['id']}/members/$ref", {"@odata.id": f"{G}/directoryObjects/{u['id']}"}))
    for n, d in fixes:
        record("fix description", n, lambda n=n, d=d: graph("patch", f"/groups/{groups[n]['id']}", {"description": d}))

    users, groups, members = state()
    after = coverage(users, members)
    json.dump(dict(before=before, after=after, held=[dict(group=group_name(*k), reason=v) for k, v in HELD.items()]),
              open(os.path.join(EVID, f"coverage_{stamp}.json"), "w"), indent=1)
    json.dump(log, open(os.path.join(EVID, f"change_log_{stamp}.json"), "w"), indent=1)
    print(f"\n{sum(l['result'] == 'ok' for l in log)}/{len(log)} changes applied.")
    print(f"Coverage AFTER: {sum(not r['missing'] for r in after)}/{len(after)} users fully match the matrix; "
          f"{sum(len(r['missing']) for r in after)} missing; {sum(len(r['extra']) for r in after)} extra. Evidence in {EVID}")


if __name__ == "__main__":
    main()
