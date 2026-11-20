"""Step 7 - Summarise the latest Azure Policy compliance states into evidence/07_compliance_summary.json (read-only).

Run after 06_compliance_evidence.sh:  python 07_summarize_compliance.py
Subscription and tenant IDs are removed; only resource names are kept.
"""
import json
import os
import subprocess
from collections import defaultdict

os.environ["MSYS_NO_PATHCONV"] = "1"
AZ = "az.cmd" if os.name == "nt" else "az"


def az(*args):
    out = subprocess.run([AZ, *args, "-o", "json"], capture_output=True, text=True, check=True).stdout
    return json.loads(out) if out.strip() else None


def short(resource_id):
    parts = [x for x in resource_id.split("/") if x]
    if len(parts) == 2 and parts[0].lower() == "subscriptions":
        return "(subscription)"
    if len(parts) >= 2 and parts[-2].lower() in ("roledefinitions", "roleassignments"):
        return f"({parts[-2]} {parts[-1][:8]}...)"
    return parts[-1]


summary = {}
for name in ["hvmc-guardrails", "hvmc-tags-hvmc-cloudsecurity-rg", "hvmc-tags-hvmc-keyvault-rg", "hvmc-hipaa-hitrust"]:
    states = az("policy", "state", "list", "--top", "5000", "--filter", f"policyAssignmentName eq '{name}'",
                "--query", "[].{ref:policyDefinitionReferenceId,def:policyDefinitionName,state:complianceState,"
                           "res:resourceId,type:resourceType,groups:policyDefinitionGroupNames,time:timestamp}")
    per_resource = defaultdict(set)
    per_policy = defaultdict(lambda: defaultdict(set))
    ref_to_def = {}
    groups_nc, groups_all = set(), set()
    for s in states:
        per_resource[s["res"].lower()].add(s["state"])
        per_policy[s["ref"]][s["state"]].add(short(s["res"]))
        ref_to_def[s["ref"]] = s["def"]
        for g in s.get("groups") or []:
            groups_all.add(g)
            if s["state"] == "NonCompliant":
                groups_nc.add(g)
    res_nc = [r for r, st in per_resource.items() if "NonCompliant" in st]
    res_ok = [r for r, st in per_resource.items() if st == {"Compliant"}]
    pol_nc = {p: sorted(v["NonCompliant"]) for p, v in per_policy.items() if v.get("NonCompliant")}
    summary[name] = {
        "evaluations": len(states),
        "latest_evaluation": max((s["time"] for s in states), default=None),
        "resources_evaluated": len(per_resource),
        "resources_compliant": len(res_ok),
        "resources_noncompliant": len(res_nc),
        "policies_evaluated": len(per_policy),
        "policies_noncompliant": len(pol_nc),
        "noncompliant_by_policy": pol_nc,
        "control_groups": len(groups_all),
        "control_groups_noncompliant": len(groups_nc),
        "_ref_to_def": {r: ref_to_def[r] for r in pol_nc},
    }

# Display names for the non-compliant HIPAA policies (the reference IDs are GUIDs)
names = {}
for ref in summary["hvmc-hipaa-hitrust"]["noncompliant_by_policy"]:
    try:
        names[ref] = az("policy", "definition", "show", "-n", summary["hvmc-hipaa-hitrust"]["_ref_to_def"][ref],
                        "--query", "displayName")
    except subprocess.CalledProcessError:
        names[ref] = ref
summary["hvmc-hipaa-hitrust"]["policy_display_names"] = names

with open("evidence/07_compliance_summary.json", "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)
for k, v in summary.items():
    print(k, {x: v[x] for x in ["resources_evaluated", "resources_compliant", "resources_noncompliant",
                                "policies_evaluated", "policies_noncompliant", "control_groups",
                                "control_groups_noncompliant", "latest_evaluation"]})
for ref, res in summary["hvmc-hipaa-hitrust"]["noncompliant_by_policy"].items():
    print("  HIPAA NC:", names.get(ref), "->", res)
print("Guardrails NC:", summary["hvmc-guardrails"]["noncompliant_by_policy"])
