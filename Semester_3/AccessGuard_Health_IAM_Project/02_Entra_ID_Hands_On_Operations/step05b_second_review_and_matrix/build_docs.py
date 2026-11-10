"""Second access review (HVMC-AR-2026-Q4-R2) report + User Access Matrix v2, from the read-only snapshot
step5_access_review/review_data_R2.json (10 Nov 2026). No names of the tenant, IDs or e-mail addresses are printed."""
import json, os, subprocess, sys, collections
HERE = os.path.dirname(os.path.abspath(__file__)); BASE = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(BASE, "step2_rbac_v2")); sys.path.insert(0, os.path.expanduser("~/Downloads/HVMC_Crypto_Reports"))
from rbac_v2 import MATRIX, group_name
from report_common import CSS, table
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
S5 = os.path.join(BASE, "step5_access_review")
data = json.load(open(os.path.join(S5, "review_data_R2.json")))
q4 = json.load(open(os.path.join(S5, "review_items_Q4.json"))); r2 = json.load(open(os.path.join(S5, "review_items_R2.json")))
cmp_ = json.load(open(os.path.join(S5, "HVMC-AR-2026-Q4-R2_comparison.json")))
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
RUN = '<div class="runhead">AccessGuard Health &nbsp;|&nbsp; Horizon Valley Medical Center &nbsp;|&nbsp; Healthcare IAM Operations Simulation</div>'

def pdf(name, title, body):
    h = os.path.join(HERE, name + ".html"); p = os.path.join(HERE, name + ".pdf")
    open(h, "w").write(f'<!doctype html><html><head><meta charset="utf-8"><title>{title}</title><style>{CSS} table{{font-size:9pt}}</style></head><body>{RUN}{body}</body></html>')
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={p}", "file://" + h], capture_output=True, check=True)
    os.remove(h); print("wrote", p)

# ---------------- User Access Matrix v2 ----------------
APPS = ["EHR", "PharmacySystem", "LIS", "Payroll", "HRPortal", "FinanceERP", "ITAdmin", "Scheduling", "SecurityPortal", "VPN"]
LBL = {"EHR": "EHR", "PharmacySystem": "Pharmacy", "LIS": "Lab (LIS)", "Payroll": "Payroll", "HRPortal": "HR Portal", "FinanceERP": "Finance ERP",
       "ITAdmin": "IT Admin", "Scheduling": "Scheduling", "SecurityPortal": "Security Portal", "VPN": "VPN"}
users = [u for u in data["users"]]; byid = {u["id"]: u for u in users}
member_of = collections.defaultdict(set)
for g, mem in data["groups"].items():
    for m in mem: member_of[m].add(g)
staff = [u for u in users if u.get("department") in MATRIX and not (u.get("employeeId") or "").startswith("HVMC-ADM")]   # admin accounts are in section 2
dept_count = collections.Counter(u["department"] for u in staff if u["accountEnabled"])
check = []
for u in staff:
    want = {group_name(u["department"], a, x) for a, x in MATRIX[u["department"]].items()} if u["accountEnabled"] else set()
    have = {g for g in member_of[u["id"]] if g.startswith("SG-") and "-KeyVault-" not in g}
    check.append((u, want, have, want == have))
ok = sum(c[3] for c in check)
mism = [c for c in check if not c[3]]

rows = []
for d in MATRIX:
    rows.append([f"<b>{d}</b>", str(dept_count.get(d, 0))] + [MATRIX[d].get(a, "—").replace("Read", "R").replace("Admin", "A").replace("Limited", "L") for a in APPS])
special = [
    ["IAM administrator (cloud-only)", "Global Administrator", "Tenant administration; Key Vault Secrets Officer on hvmc-accessguard-kv", "IAM admin"],
    ["Emergency Access 01 / 02", "Global Administrator", "Break-glass only; quarterly sign-in test (~28 Jan 2027)", "Security Supervisor"],
    ["HVMC Help Desk Admin", "Authentication Administrator + Reports Reader", "MFA resets for normal users; audit-log reading (Step 10)", "IT Manager"],
    ["SG-IT-KeyVault-Admin (Kevin O'Brien)", "Key Vault Administrator", "Vault scope only", "IT Manager"],
    ["SG-Security-KeyVault-Read (Denise Coleman)", "Key Vault Reader", "Secret names only, no values", "Security Supervisor"],
    ["SG-Services-KeyVault-SecretsUser (HVMC Lab Results Sync app)", "Key Vault Secrets User", "Reads its secret; certificate auth; also Graph GroupMember.Read.All", "IAM admin"],
]
body = f"""<h1>User Access Matrix v2</h1><div class="sub">Board: Week 10 — Update User Access Matrix · 10 November 2026</div>
<div class="tag">Final matrix for the fully built environment (Entra ID RBAC v2, enterprise apps, JML, Key Vault and admin roles),
cross-checked against the live tenant (read-only snapshot, 10 Nov 2026).</div>
<table class="meta"><tbody><tr><td>Prepared By</td><td>Sabitha S Karanavar</td></tr><tr><td>Source</td><td>rbac_v2.MATRIX (design) + read-only Microsoft Graph / Azure snapshot (actual)</td></tr>
<tr><td>Cross-check result</td><td><b>{ok} of {len(check)}</b> department accounts match the matrix exactly ({len(mism)} difference{'s' if len(mism)!=1 else ''})</td></tr></tbody></table>
<h2>1. Department roles × applications</h2>
<p>RW = read and write · R = read · A = administer · L = limited · — = no access. Access is granted only through
<code>SG-&lt;Dept&gt;-&lt;App&gt;-&lt;Access&gt;</code> security groups; app assignments follow the groups.</p>
{table(["Role (department)", "Active staff"] + [LBL[a] for a in APPS], rows)}
<h2>2. Privileged, administrative and non-human access</h2>
{table(["Identity", "Role", "Scope / purpose", "Owner / reviewer"], special, ["30%","24%","30%","16%"])}
<h2>3. Cross-check against the live tenant</h2>
<p>For every account in a department, the expected groups from the matrix were compared with its actual SG-* groups
(Key Vault groups are listed in section 2). Disabled accounts are expected to hold no groups.</p>
{table(["Account", "Department", "Status", "Expected groups", "Actual groups", "Result"],
       [[u["displayName"], u["department"], "Enabled" if u["accountEnabled"] else "Disabled", str(len(w)), str(len(h)), "✅ match" if m else "⚠️ differs"]
        for u, w, h, m in sorted(check, key=lambda c: (c[0]["department"], c[0]["displayName"]))], ["26%","16%","12%","15%","15%","16%"])}
{"".join(f'<div class="box warn"><b>Difference:</b> {u["displayName"]} ({u["department"]}) — missing: {", ".join(sorted(w-h)) or "none"}; extra: {", ".join(sorted(h-w)) or "none"}</div>' for u,w,h,m in mism)}
<h2>4. Changes since the first matrix (Week 5 / RBAC v2, 20 Oct)</h2>
<ul><li>Joiner Ethan Morales (Laboratory), mover Jason Park (IT → Security, IT groups removed first), leaver Victor Mensah (all access removed) — JML-204–206.</li>
<li>Two break-glass Global Administrators and a least-privileged help-desk administrator added.</li>
<li>Key Vault roles mapped to three new groups at vault scope (Key Vault Task 2); the HVMC Lab Results Sync app is the only non-human member.</li>
<li>Contractor (Carlos Diaz) disabled with no groups since JML-203.</li></ul>
"""
pdf("HVMC_User_Access_Matrix_v2", "HVMC User Access Matrix v2", body)

wb = Workbook(); ws = wb.active; ws.title = "Matrix v2"
ws.append(["Role (department)", "Active staff"] + [LBL[a] for a in APPS])
for d in MATRIX: ws.append([d, dept_count.get(d, 0)] + [MATRIX[d].get(a, "—") for a in APPS])
for c in ws[1]: c.font = Font(bold=True, color="FFFFFF"); c.fill = PatternFill("solid", fgColor="1F3864")
ws2 = wb.create_sheet("Privileged & NHI"); ws2.append(["Identity", "Role", "Scope / purpose", "Owner / reviewer"]); [ws2.append(r) for r in special]
ws3 = wb.create_sheet("Cross-check"); ws3.append(["Account", "Department", "Status", "Expected groups", "Actual groups", "Result"])
for u, w, h, m in check: ws3.append([u["displayName"], u["department"], "Enabled" if u["accountEnabled"] else "Disabled", "; ".join(sorted(w)), "; ".join(sorted(h)), "match" if m else "differs"])
for s in (ws2, ws3):
    for c in s[1]: c.font = Font(bold=True, color="FFFFFF"); c.fill = PatternFill("solid", fgColor="1F3864")
for s in (ws, ws2, ws3):
    for col in s.columns: s.column_dimensions[col[0].column_letter].width = 22
wb.save(os.path.join(HERE, "HVMC_User_Access_Matrix_v2.xlsx")); print("wrote matrix xlsx")

# ---------------- Second access review report ----------------
q4keep = sum(i["recommendation"] == "Keep" for i in q4); r2rec = collections.Counter(i["recommendation"] for i in r2)
real_new = [i for i in cmp_["new"] if not i["access"].startswith("EHR-Simulated")]
real_gone = [i for i in cmp_["gone"] if not i["access"].startswith("EHR-Simulated")]
why = {"Test Nurse - EHR": "Removed in Q4 (the only Q4 finding, R07)", "Victor Mensah": "Leaver JML-206 — deprovisioned 2 Nov",
       "Jason Park": "Mover JML-205 — IT groups removed (separation of duties)"}
body = f"""<h1>Second Access Review — HVMC-AR-2026-Q4-R2</h1><div class="sub">Board: Week 10 — Second Access Review · 10 November 2026</div>
<div class="tag">The access review process was re-run on the live tenant with the same rules and compared with the first review
(HVMC-AR-2026-Q4, 20 October). The goal: a shorter, cleaner findings list.</div>
<table class="meta"><tbody><tr><td>Prepared By</td><td>Sabitha S Karanavar</td></tr>
<tr><td>Method</td><td>collect_review_data.py (read-only Graph + Azure snapshot) → build_review_pack.py → comparison with Q4</td></tr>
<tr><td>Scope</td><td>All SG-* memberships, direct app assignments, Entra directory roles, Azure RBAC (incl. Key Vault)</td></tr>
<tr><td>Cost / changes</td><td>$0 · read-only, no access was changed</td></tr></tbody></table>
<h2>1. Result</h2>
{table(["", "First review (Q4, 20 Oct)", "Second review (R2, 10 Nov)"], [
    ["Review lines", str(len(q4)), str(len(r2))],
    ["Recommended Keep", str(q4keep), str(r2rec.get("Keep", 0))],
    ["Findings (Remove)", str(len(q4) - q4keep), str(r2rec.get("Remove", 0))],
    ["Lines unchanged", "—", str(len(r2) - len(cmp_["new"]))]], ["40%", "30%", "30%"])}
<div class="box"><b>Cleaner findings list:</b> the one Q4 finding (a disabled test account holding an Azure data role on the ePHI storage)
was fixed, and the second review found <b>no new access to remove</b>. Every change since Q4 is explained by an approved JML event,
change ticket or Key Vault task.</div>
<h2>2. What changed since the first review</h2>
{table(["Account / identity", "Access", "Change", "Explained by"],
       [[i["user"], i["access"], "Added", i["reason"]] for i in real_new] + [[i["user"], i["access"], "Removed", why.get(i["user"], "")] for i in real_gone],
       ["26%", "34%", "10%", "30%"])}
<p><i>Not a real change:</i> the 11 legacy EHR-Simulated assignments appear with a different role label ("User" instead of
"Default access") because the new snapshot reads the app's role name. The assignments are the same.</p>
<h2>3. Open points for the next review (HVMC-AR-2027-Q1, January 2027)</h2>
<ul><li><b>EHR-Simulated:</b> 12 direct (legacy) assignments are still kept under the Q4 “manage” decision — decide whether to retire the app.</li>
<li>Two single-holder admin roles (Authentication Administrator, Reports Reader) — confirm the help-desk account is still needed.</li>
<li>Break-glass sign-in test due ~28 Jan 2027; Defender for Storage managed identities (see the Q1 preparation notes).</li></ul>
<h2>4. Evidence</h2><p>HVMC-AR-2026-Q4-R2_Review_Pack.xlsx (103 lines with reviewer, flag, recommendation and justification) and the
comparison file HVMC-AR-2026-Q4-R2_comparison.json (no tenant identifiers).</p>
"""
pdf("HVMC_Second_Access_Review_HVMC-AR-2026-Q4-R2", "HVMC Second Access Review", body)
print("matrix check:", ok, "/", len(check), "| differences:", [(c[0]["displayName"]) for c in mism])
