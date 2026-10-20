"""
HVMC Healthcare IAM - Step 1: identity hygiene in Microsoft Entra ID (Free tier, $0).

Horizon Valley Medical Center | Author: Sabitha S Karanavar

Fixes the baseline findings:
  F1  no user has a manager           -> set each user's manager (department lead)
  F2  no employee ID                  -> assign HVMC employee IDs (contractors: HVMC-C###)
  F5  contractor has no end/sponsor   -> employeeType=Contractor, sponsor recorded, leave date set
  F4  shared test account enabled     -> disable "Test Nurse - EHR" (R07)

    python3 identity_hygiene.py            # DRY RUN: shows every change, changes nothing
    python3 identity_hygiene.py --apply    # applies, then writes before/after evidence

The signed-in administrator's own account is never modified.
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
DOMAIN = "sabithaskaranavargmail.onmicrosoft.com"
CONTRACT_END = "2026-12-31T23:59:59Z"

# department -> (lead, [members in employee-ID order])
ORG = {
    "Doctors":         ("Sarah Chen",     ["Aisha Rahman", "James Okafor", "Maria Gonzalez", "Peter Novak"]),
    "Nursing":         ("Angela Brooks",  ["Emily Carter", "Lisa Tran", "Monica Alvarez", "Noah Fischer", "Robert Kim", "Tyrone Jackson"]),
    "Pharmacy":        ("David Patel",    ["Marcus Webb", "Nicole Reyes"]),
    "Laboratory":      ("Elena Petrova",  ["Priya Nair", "Thomas Wright"]),
    "Human Resources": ("Daniel Osei",    ["Karen Smith"]),
    "Finance":         ("Brian Adeyemi",  ["Michael Torres"]),
    "IT":              ("Kevin O'Brien",  ["Fatima Ali", "Jason Park"]),
    "Security":        ("Denise Coleman", ["Anthony Ruiz"]),
    "Reception":       ("Grace Nguyen",   ["Victor Mensah"]),
}
DEPT_CODE = {"Doctors": 10, "Nursing": 11, "Pharmacy": 12, "Laboratory": 13, "Human Resources": 14,
             "Finance": 15, "IT": 16, "Security": 17, "Reception": 18}
CONTRACTOR = ("Carlos Diaz", "Kevin O'Brien")          # contractor, sponsor
TEST_ACCOUNT = "Test Nurse - EHR"


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


def snapshot():
    sel = "id,displayName,userPrincipalName,department,jobTitle,accountEnabled,employeeId,employeeType,employeeLeaveDateTime"
    users = graph("get", f"/users?$select={sel}&$expand=manager($select=displayName)&$top=200")["value"]
    return {u["displayName"]: u for u in users}


def plan(users, me):
    changes = []                                       # (user, description, method, path, body)
    def uid(name):
        if name not in users:
            raise SystemExit(f"user not found: {name}")
        return users[name]["id"]

    for dept, (lead, members) in ORG.items():
        code = DEPT_CODE[dept]
        for i, name in enumerate([lead] + members, start=1):
            u = users[name]
            if u["userPrincipalName"].lower() == me:
                continue
            eid = f"HVMC-{code}{i:02d}"
            if u.get("employeeId") != eid or u.get("employeeType") != "Employee":
                changes.append((name, f"employeeId {u.get('employeeId')} -> {eid}; employeeType -> Employee",
                                "patch", f"/users/{u['id']}", {"employeeId": eid, "employeeType": "Employee"}))
            if name != lead:
                cur = (u.get("manager") or {}).get("displayName")
                if cur != lead:
                    changes.append((name, f"manager {cur} -> {lead}", "put", f"/users/{u['id']}/manager/$ref",
                                    {"@odata.id": f"{G}/users/{uid(lead)}"}))

    c, sponsor = CONTRACTOR
    u = users[c]
    body = {"employeeId": "HVMC-C001", "employeeType": "Contractor"}
    if (u.get("employeeId"), u.get("employeeType")) != ("HVMC-C001", "Contractor"):
        changes.append((c, "employeeId -> HVMC-C001; employeeType -> Contractor", "patch", f"/users/{u['id']}", body))
    if (u.get("manager") or {}).get("displayName") != sponsor:
        changes.append((c, f"sponsor/manager -> {sponsor}", "put", f"/users/{u['id']}/manager/$ref",
                        {"@odata.id": f"{G}/users/{uid(sponsor)}"}))
    if not (u.get("employeeLeaveDateTime") or "").startswith(CONTRACT_END[:10]):
        changes.append((c, f"contract end (employeeLeaveDateTime) -> {CONTRACT_END[:10]}", "patch", f"/users/{u['id']}",
                        {"employeeLeaveDateTime": CONTRACT_END}))

    t = users[TEST_ACCOUNT]
    if t["accountEnabled"]:
        changes.append((TEST_ACCOUNT, "accountEnabled true -> false (shared test account, R07)", "patch",
                        f"/users/{t['id']}", {"accountEnabled": False}))
    return changes


def main():
    apply = "--apply" in sys.argv
    me = az("account", "show")["user"]["name"].lower()
    me_upn = graph("get", "/me?$select=userPrincipalName")["userPrincipalName"].lower()
    before = snapshot()
    changes = plan(before, me_upn)
    print(f"{'APPLY' if apply else 'DRY RUN'} - {len(changes)} change(s) planned; signed in as {me}\n")
    for name, desc, *_ in changes:
        print(f"  {name:<20} {desc}")
    if not apply:
        print("\nNothing was changed. Run with --apply to make these changes.")
        return
    os.makedirs(EVID, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    json.dump(before, open(os.path.join(EVID, f"before_{stamp}.json"), "w"), indent=1)
    log = []
    for name, desc, method, path, body in changes:
        try:
            graph(method, path, body)
            ok, err = True, ""
        except Exception as e:
            ok, err = False, str(e)
        log.append(dict(time=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), user=name, change=desc,
                        result="ok" if ok else "FAILED", error=err, by=me, ticket="HVMC-IAM-CHG-101"))
        print(f"  [{'ok' if ok else 'FAILED'}] {name}: {desc} {err}")
    after = snapshot()
    json.dump(after, open(os.path.join(EVID, f"after_{stamp}.json"), "w"), indent=1)
    json.dump(log, open(os.path.join(EVID, f"change_log_{stamp}.json"), "w"), indent=1)
    print(f"\n{sum(l['result'] == 'ok' for l in log)}/{len(log)} applied. Evidence in {EVID}")


if __name__ == "__main__":
    main()
