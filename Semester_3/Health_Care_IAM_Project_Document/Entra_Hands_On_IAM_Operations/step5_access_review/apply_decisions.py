"""
HVMC Healthcare IAM - Step 5: record reviewer decisions and carry out removals (campaign HVMC-AR-2026-Q4).

Horizon Valley Medical Center | Author: Sabitha S Karanavar

Decision source: the recommendation on each line, accepted by the named reviewer ("go with recommendation",
20 Oct 2026), unless a Decision was already typed into the review pack. Writes the decided pack, then:
  * "Remove" lines -> removes the group membership / direct app assignment / Azure role assignment
  * legacy app decision "manage" -> runs the step 3 sync, which now drives EHR-Simulated from the EHR groups

    python3 apply_decisions.py            # DRY RUN: decisions and actions, nothing changed
    python3 apply_decisions.py --apply
"""
import datetime as dt
import json
import os
import subprocess
import sys

from openpyxl import load_workbook

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "step2_rbac_v2"))
from rbac_v2 import az, graph, G          # noqa: E402

CAMPAIGN = "HVMC-AR-2026-Q4"
PACK = os.path.join(HERE, f"{CAMPAIGN}_Review_Pack.xlsx")
DECIDED = os.path.join(HERE, f"{CAMPAIGN}_Review_Pack_DECIDED.xlsx")
TODAY = dt.date.today().isoformat()


def reviewer_name(r):
    return r.split(" (")[0]


def decide():
    wb = load_workbook(PACK)
    ws = wb["Review"]
    head = [c.value for c in ws[1]]
    col = {h: i + 1 for i, h in enumerate(head)}
    lines = []
    for row in range(2, ws.max_row + 1):
        v = {h: ws.cell(row, col[h]).value for h in head}
        decision = v["Decision"] or ("Keep" if v["Recommendation"] in ("Keep", "Reviewer decides") else v["Recommendation"])
        just = v["Justification"] or (v["Reason"] + " - recommendation accepted by reviewer")
        ws.cell(row, col["Decision"], decision)
        ws.cell(row, col["Justification"], just)
        ws.cell(row, col["Decided by"], reviewer_name(v["Reviewer"]))
        ws.cell(row, col["Decision date"], TODAY)
        lines.append(dict(v, Decision=decision, Justification=just))
    return wb, lines


def actions(lines):
    acts = []
    for l in lines:
        if l["Decision"] != "Remove":
            continue
        if l["Access type"] == "Group":
            acts.append((l, "remove group membership"))
        elif l["Access type"] == "Direct app assignment":
            acts.append((l, "remove direct app assignment"))
        elif l["Access type"] == "Azure RBAC role":
            acts.append((l, "delete Azure role assignment"))
        else:
            acts.append((l, "MANUAL (directory role)"))
    return acts


def execute(l, what):
    if what == "remove group membership":
        u = graph("get", f"/users?$filter=displayName eq '{l['User']}'&$select=id")["value"][0]
        g = graph("get", f"/groups?$filter=displayName eq '{l['Access']}'&$select=id")["value"][0]
        graph("delete", f"/groups/{g['id']}/members/{u['id']}/$ref")
    elif what == "remove direct app assignment":
        app = l["Access"].split(" [")[0]
        u = graph("get", f"/users?$filter=displayName eq '{l['User']}'&$select=id")["value"][0]
        for a in graph("get", f"/users/{u['id']}/appRoleAssignments")["value"]:
            if a["resourceDisplayName"] == app:
                graph("delete", f"/users/{u['id']}/appRoleAssignments/{a['id']}")
    elif what == "delete Azure role assignment":
        role, scope_name = l["Access"].split(" on ")
        upn = graph("get", f"/users?$filter=displayName eq '{l['User']}'&$select=userPrincipalName")["value"][0]["userPrincipalName"]
        ids = [r["id"] for r in az("role", "assignment", "list", "--all", "--assignee", upn, "-o", "json")
               if r["roleDefinitionName"] == role and r["scope"].endswith("/" + scope_name)]
        if not ids:
            raise RuntimeError("assignment not found")
        az("role", "assignment", "delete", "--ids", *ids)
    else:
        raise RuntimeError("needs a manual change")


def main():
    apply = "--apply" in sys.argv
    wb, lines = decide()
    acts = actions(lines)
    keep = sum(l["Decision"] == "Keep" for l in lines)
    print(f"{'APPLY' if apply else 'DRY RUN'} {CAMPAIGN}: {len(lines)} lines decided - Keep {keep}, Remove {len(lines) - keep}\n")
    print("Removals:")
    for l, what in acts:
        print(f"  - {l['User']}: {l['Access']}  ({what}; reviewer {reviewer_name(l['Reviewer'])})")
    print("\nLegacy app decision 'manage': step 3 sync drives EHR-Simulated from SG-Doctors-EHR-RW + SG-Nursing-EHR-RW")
    if not apply:
        print("\nNothing was changed. Run with --apply to record the decisions and make these changes.")
        return
    wb.save(DECIDED)
    log = []
    for l, what in acts:
        try:
            execute(l, what)
            res, err = "ok", ""
        except Exception as e:
            res, err = "FAILED", str(e)
        log.append(dict(time=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), user=l["User"], access=l["Access"],
                        action=what, reviewer=reviewer_name(l["Reviewer"]), result=res, error=err))
        print(f"  [{res}] {l['User']}: {l['Access']} {err}")
    p = subprocess.run([sys.executable, os.path.join(ROOT, "step3_enterprise_apps", "enterprise_apps.py"), "--apply"],
                       capture_output=True, text=True)
    sync = next((x for x in p.stdout.splitlines() if "applied" in x), p.stderr.strip()[-200:])
    log.append(dict(time=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), action="group-driven app sync (incl. EHR-Simulated)",
                    result=sync))
    json.dump(dict(campaign=CAMPAIGN, decided=TODAY, lines=len(lines), keep=keep, removals=log),
              open(os.path.join(HERE, f"{CAMPAIGN}_actions_log.json"), "w"), indent=1)
    print(f"\napp sync: {sync}\ndecided pack: {DECIDED}")


if __name__ == "__main__":
    main()
