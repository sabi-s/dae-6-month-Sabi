"""
HVMC Healthcare IAM - Step 5: access review campaign HVMC-AR-2026-Q4 (Entra ID Free, $0).

Horizon Valley Medical Center | Author: Sabitha S Karanavar

Builds the review pack (Excel) from review_data.json (read-only snapshot of the tenant):
  * every SG-* group membership       (HVMC app access is derived from these, so it is reviewed through them)
  * every direct (non-group) app assignment, e.g. the legacy EHR-Simulated app
  * directory roles (Global Administrator) and Azure RBAC role assignments
  * disabled accounts that still hold any access
Reviewer = the user's manager (Step 1); department leads, test/admin accounts and privileged roles go to the
IAM administrator and the Security Supervisor. Every line gets a rule-based flag and a recommendation; the
reviewer records Keep / Remove with a justification. apply_decisions.py then carries out the removals.

    python3 build_review_pack.py [--ehr-simulated retire|manage|review]
"""
import json
import os
import sys

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "step2_rbac_v2"))
from rbac_v2 import MATRIX, group_name          # noqa: E402

CAMPAIGN, DUE = "HVMC-AR-2026-Q4", "2026-10-31"
IAM_ADMIN, SECURITY = "Sabitha S Karanavar (IAM Administrator)", "Denise Coleman (Security Supervisor)"
NAVY, AMBER, RED, GREEN = "1F3864", "FFF2CC", "FDE2DF", "E6F2E8"


def load():
    return json.load(open(os.path.join(HERE, "review_data.json")))


def sp_name(object_id):
    """Display name of a service principal (read-only Graph call); falls back to the id."""
    try:
        from rbac_v2 import graph
        return graph("get", f"/servicePrincipals/{object_id}?$select=displayName")["displayName"]
    except Exception:
        return object_id


def rows(data, ehr_mode):
    users = {u["id"]: u for u in data["users"]}
    out = []

    def reviewer(u):
        if u.get("userType") == "Guest" or "#EXT#" in u["userPrincipalName"] or u.get("department") in ("Test Accounts", "Lab Administration"):
            return IAM_ADMIN
        m = (u.get("manager") or {}).get("displayName")
        return f"{m} (manager)" if m else IAM_ADMIN + " - department lead"

    def add(u, kind, access, expected, flag, rec, reason, rev=None):
        out.append(dict(reviewer=rev or reviewer(u), user=u["displayName"], employeeId=u.get("employeeId") or "", department=u.get("department") or "",
                        title=u.get("jobTitle") or "", status="Enabled" if u["accountEnabled"] else "DISABLED",
                        employeeType=u.get("employeeType") or "", kind=kind, access=access, expected=expected, flag=flag,
                        recommendation=rec, reason=reason))

    for g, members in sorted(data["groups"].items()):
        if not g.startswith("SG-"):
            continue
        for uid in members:
            u = users.get(uid)
            if not u:
                continue
            want = {group_name(u.get("department"), a, x) for a, x in MATRIX.get(u.get("department"), {}).items()}
            if not u["accountEnabled"]:
                add(u, "Group", g, "No", "DISABLED ACCOUNT", "Remove", "Disabled account still holds access")
            elif g in want:
                add(u, "Group", g, "Yes", "", "Keep", "Matches RBAC v2 for department")
            else:
                add(u, "Group", g, "No", "NOT IN RBAC", "Remove", f"Not granted to {u.get('department')} by RBAC v2")

    for app, assigns in sorted(data["apps"].items()):
        if app.startswith("HVMC "):
            continue                                  # derived from groups: reviewed through the group lines
        for a in assigns:
            u = users.get(a["principalId"])
            if not u:
                continue
            rec, why = {"retire": ("Remove", "Legacy app retired; access provided by HVMC Electronic Health Record via groups"),
                        "manage": ("Keep", "Legacy app to be brought under group-driven sync (SG-Doctors/Nursing-EHR-RW)"),
                        "review": ("Reviewer decides", "Legacy app with direct assignment, not group-driven (finding F-JML-01)")}[ehr_mode] \
                if app == "EHR-Simulated" else ("Reviewer decides", "Direct app assignment outside RBAC groups")
            add(u, "Direct app assignment", f"{app} [{a['role'] or 'Default access'}]", "Legacy", "LEGACY / DIRECT", rec, why)

    for role, members in data["dirroles"].items():
        for uid in members:
            u = users.get(uid)
            if u:
                add(u, "Entra directory role", role, "Privileged", "PRIVILEGED - SOLE HOLDER" if len(members) == 1 else "PRIVILEGED",
                    "Keep", "Only Global Administrator; keep, but add a second admin and a break-glass account (risk R04)", SECURITY)

    for r in data.get("azure_rbac", []):
        name = r.get("principalName") or r.get("principalId")
        u = next((x for x in users.values() if x["userPrincipalName"] == name or x["id"] == r.get("principalId")), None)
        scope = r["scope"].split("/")[-1] or r["scope"]
        if u:
            if not u["accountEnabled"]:
                add(u, "Azure RBAC role", f"{r['roleDefinitionName']} on {scope}", "No", "DISABLED ACCOUNT", "Remove",
                    "Disabled shared test account still holds an Azure data role on the ePHI storage account (risk R07)", SECURITY)
            else:
                add(u, "Azure RBAC role", f"{r['roleDefinitionName']} on {scope}", "Privileged", "PRIVILEGED", "Keep",
                    "Subscription owner/administrator", SECURITY)
        else:
            out.append(dict(reviewer=SECURITY, user=f"{sp_name(r.get('principalId'))} (Microsoft service)", employeeId="", department="Platform", title="",
                            status="n/a", employeeType="Workload identity", kind="Azure RBAC role",
                            access=f"{r['roleDefinitionName']} on {scope}", expected="Platform", flag="WORKLOAD IDENTITY",
                            recommendation="Keep", reason="Granted by Microsoft Defender / Sentinel onboarding (change HVMC-CHG-02)"))
    return out


def build(ehr_mode):
    data = load()
    items = rows(data, ehr_mode)
    wb = Workbook()
    ws = wb.active
    ws.title = "Instructions"
    info = [
        ("Access review campaign", CAMPAIGN), ("Organisation", "Horizon Valley Medical Center"), ("Scope", "All Entra ID SG-* group memberships "
         "(these drive app access), direct app assignments, Entra directory roles, Azure RBAC roles, disabled accounts"),
        ("Reviewers", "Each user's manager; department leads and test/admin accounts: IAM Administrator; privileged roles: Security Supervisor"),
        ("Due date", DUE), ("Regulation", "HIPAA 45 CFR 164.308(a)(3)(ii)(B)-(C) and 164.308(a)(4)(ii)(C): access authorisation, establishment and modification"),
        ("How to review", "For every line choose Keep or Remove in the Decision column and give a justification. "
         "Lines flagged amber/red need particular attention. Unanswered lines are escalated after the due date."),
        ("After review", "apply_decisions.py removes every 'Remove' line and logs it under ticket HVMC-AR-2026-Q4."),
        ("Legacy EHR-Simulated recommendation", {"retire": "Retire (remove all assignments)", "manage": "Bring under group-driven sync",
                                                 "review": "Reviewer decides per line"}[ehr_mode])]
    ws["A1"] = "HVMC Access Review - " + CAMPAIGN
    ws["A1"].font = Font(bold=True, size=14, color=NAVY)
    for i, (k, v) in enumerate(info, start=3):
        ws.cell(i, 1, k).font = Font(bold=True)
        ws.cell(i, 2, v).alignment = Alignment(wrap_text=True, vertical="top")
    ws.column_dimensions["A"].width, ws.column_dimensions["B"].width = 34, 110

    rv = wb.create_sheet("Review")
    head = ["Reviewer", "User", "Employee ID", "Department", "Job title", "Account", "Type", "Access type", "Access",
            "Expected by RBAC v2", "Flag", "Recommendation", "Reason", "Decision", "Justification", "Decided by", "Decision date"]
    rv.append(head)
    for c in range(1, len(head) + 1):
        cell = rv.cell(1, c)
        cell.font, cell.fill = Font(bold=True, color="FFFFFF"), PatternFill("solid", fgColor=NAVY)
        cell.alignment = Alignment(wrap_text=True, vertical="center")
    items.sort(key=lambda r: (r["reviewer"], r["user"], r["kind"], r["access"]))
    for r in items:
        rv.append([r["reviewer"], r["user"], r["employeeId"], r["department"], r["title"], r["status"], r["employeeType"], r["kind"],
                   r["access"], r["expected"], r["flag"], r["recommendation"], r["reason"], "", "", "", ""])
        fill = RED if r["recommendation"] == "Remove" else AMBER if r["flag"] else None
        if fill:
            for c in range(1, len(head) + 1):
                rv.cell(rv.max_row, c).fill = PatternFill("solid", fgColor=fill)
    dv = DataValidation(type="list", formula1='"Keep,Remove"', allow_blank=True)
    rv.add_data_validation(dv)
    dv.add(f"N2:N{rv.max_row}")
    for i, w in enumerate([34, 20, 12, 15, 22, 10, 12, 20, 44, 12, 22, 16, 58, 11, 34, 18, 13], start=1):
        rv.column_dimensions[get_column_letter(i)].width = w
    rv.freeze_panes, rv.auto_filter.ref = "C2", f"A1:{get_column_letter(len(head))}{rv.max_row}"

    sm = wb.create_sheet("Summary")
    sm.append(["Reviewer", "Lines", "Recommended Keep", "Recommended Remove", "Reviewer decides", "Flagged"])
    for c in range(1, 7):
        sm.cell(1, c).font, sm.cell(1, c).fill = Font(bold=True, color="FFFFFF"), PatternFill("solid", fgColor=NAVY)
    for rev in sorted({r["reviewer"] for r in items}):
        rs = [r for r in items if r["reviewer"] == rev]
        sm.append([rev, len(rs), sum(r["recommendation"] == "Keep" for r in rs), sum(r["recommendation"] == "Remove" for r in rs),
                   sum(r["recommendation"] == "Reviewer decides" for r in rs), sum(bool(r["flag"]) for r in rs)])
    sm.append(["TOTAL", len(items), sum(r["recommendation"] == "Keep" for r in items), sum(r["recommendation"] == "Remove" for r in items),
               sum(r["recommendation"] == "Reviewer decides" for r in items), sum(bool(r["flag"]) for r in items)])
    sm.cell(sm.max_row, 1).font = Font(bold=True)
    sm.column_dimensions["A"].width = 52
    for col in "BCDEF":
        sm.column_dimensions[col].width = 18

    path = os.path.join(HERE, f"{CAMPAIGN}_Review_Pack.xlsx")
    wb.save(path)
    json.dump(items, open(os.path.join(HERE, "review_items.json"), "w"), indent=1)
    return path, items


if __name__ == "__main__":
    mode = sys.argv[sys.argv.index("--ehr-simulated") + 1] if "--ehr-simulated" in sys.argv else "review"
    path, items = build(mode)
    by = {}
    for r in items:
        by.setdefault(r["flag"] or "(no flag)", []).append(r)
    print(path, "-", len(items), "review lines")
    for f, rs in sorted(by.items(), key=lambda x: -len(x[1])):
        print(f"  {f:<26} {len(rs):>3}  e.g. {rs[0]['user']}: {rs[0]['access']} -> {rs[0]['recommendation']}")
