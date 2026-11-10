"""Read-only snapshot of the tenant for an access review (same format as review_data.json).
Uses the Azure CLI login (az rest / az role assignment list). Changes nothing.
    python3 collect_review_data.py OUT.json
"""
import json, subprocess, sys

def az(*a):
    r = subprocess.run(["az", *a, "-o", "json"], capture_output=True, text=True)
    if r.returncode: sys.exit(r.stderr)
    return json.loads(r.stdout or "null")

def graph_all(url):
    out = []
    while url:
        d = az("rest", "--method", "get", "--url", url)
        out += d.get("value", []); url = d.get("@odata.nextLink")
    return out

G = "https://graph.microsoft.com/v1.0"
sel = "id,displayName,userPrincipalName,accountEnabled,department,jobTitle,employeeId,employeeType,employeeLeaveDateTime,createdDateTime,userType"
users = graph_all(f"{G}/users?$select={sel}&$expand=manager($select=displayName)&$top=200")
groups = {}
for g in graph_all(f"{G}/groups?$select=id,displayName&$top=200"):
    mem = graph_all(f"{G}/groups/{g['id']}/members?$select=id&$top=200")
    sps = graph_all(f"{G}/groups/{g['id']}/members/microsoft.graph.servicePrincipal?$select=id,displayName")
    groups[g["displayName"]] = [m["id"] for m in mem] + [s["id"] for s in sps if s["id"] not in {m["id"] for m in mem}]
apps = {}
for sp in graph_all(f"{G}/servicePrincipals?$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')&$select=id,displayName,appRoles&$top=200"):
    roles = {r["id"]: r.get("value") or r.get("displayName") for r in sp.get("appRoles", [])}
    asg = graph_all(f"{G}/servicePrincipals/{sp['id']}/appRoleAssignedTo?$top=200")
    if asg:
        apps[sp["displayName"]] = [{"principalId": a["principalId"], "principalType": a["principalType"], "role": roles.get(a["appRoleId"])} for a in asg]
dirroles = {}
for r in graph_all(f"{G}/directoryRoles?$select=id,displayName"):
    dirroles[r["displayName"]] = [m["id"] for m in graph_all(f"{G}/directoryRoles/{r['id']}/members?$select=id")]
azure_rbac = az("role", "assignment", "list", "--all")
json.dump(dict(users=users, groups=groups, apps=apps, dirroles=dirroles, azure_rbac=azure_rbac), open(sys.argv[1], "w"), indent=1)
print(f"users {len(users)} | groups {len(groups)} | apps {len(apps)} | directory roles {len(dirroles)} | azure rbac {len(azure_rbac)}")
