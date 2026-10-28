"""HVMC Healthcare IAM - hands-on Entra ID operations (Steps 1-7) deliverable -> PDF, built from the evidence files."""
import glob
import html
import importlib.util
import json
import os
import subprocess

E = html.escape
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STYLE = os.path.join(ROOT, "report_style.html")
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
OUT_PDF = os.path.join(ROOT, "HVMC_IAM_Hands_On_Entra_Operations.pdf")


def latest(pattern):
    return json.load(open(sorted(glob.glob(os.path.join(ROOT, pattern)))[-1]))


def first(pattern):
    return json.load(open(sorted(glob.glob(os.path.join(ROOT, pattern)))[0]))


def mod(path, name):
    s = importlib.util.spec_from_file_location(name, os.path.join(ROOT, path))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def table(head, rows, cls=""):
    return (f'<table class="{cls}"><tr>' + "".join(f"<th>{E(h)}</th>" for h in head) + "</tr>"
            + "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows) + "</table>")


def kv(rows):
    return '<table class="kv">' + "".join(f"<tr><td>{E(a)}</td><td>{E(b)}</td></tr>" for a, b in rows) + "</table>"


def build():
    s1_before, s1_after, s1_log = latest("step1_identity_hygiene/evidence/before_*.json"), latest("step1_identity_hygiene/evidence/after_*.json"), \
        latest("step1_identity_hygiene/evidence/change_log_*.json")
    s2_cov, s2_log = latest("step2_rbac_v2/evidence/coverage_*.json"), latest("step2_rbac_v2/evidence/change_log_*.json")
    s3_first, s3_last = first("step3_enterprise_apps/evidence/apps_*.json"), latest("step3_enterprise_apps/evidence/apps_*.json")
    jml = {k: json.load(open(os.path.join(ROOT, f"step4_jml/evidence/HVMC-JML-{n}_{k}.json"))) for n, k in (("201", "joiner"), ("202", "mover"), ("203", "leaver"))}
    ar_items = json.load(open(os.path.join(ROOT, "step5_access_review/review_items.json")))
    ar_log = json.load(open(os.path.join(ROOT, "step5_access_review/HVMC-AR-2026-Q4_actions_log.json")))
    hyg = mod("step1_identity_hygiene/identity_hygiene.py", "hyg")
    rb = mod("step2_rbac_v2/rbac_v2.py", "rb")
    apps = mod("step3_enterprise_apps/enterprise_apps.py", "apps")
    ca = mod("step6_conditional_access/ca_design.py", "ca")
    tests = json.load(open(os.path.join(ROOT, "step6_conditional_access/test_plan.json")))
    s7_before, s7_after = latest("step7_tenant_hardening/evidence/*_authorizationPolicy_before.json"), \
        latest("step7_tenant_hardening/evidence/*_authorizationPolicy_after.json")
    s7_bg = latest("step7_tenant_hardening/evidence/*_breakglass_after.json")
    th = mod("step7_tenant_hardening/tenant_hardening.py", "th")

    # ---- step 1
    org_rows = []
    for dept, (lead, members) in hyg.ORG.items():
        code = hyg.DEPT_CODE[dept]
        org_rows.append((E(dept), f"<b>{E(lead)}</b>", E(", ".join(members)), f"HVMC-{code}01 – HVMC-{code}{len(members) + 1:02d}"))
    staff_before = [u for u in s1_before.values() if u.get("department") not in (None, "Lab Administration")]
    staff_after = [u for u in s1_after.values() if u.get("department") not in (None, "Lab Administration")]
    s1_metrics = [("Users with a manager", sum(1 for u in staff_before if u.get("manager")), sum(1 for u in staff_after if u.get("manager"))),
                  ("Users with an employee ID", sum(1 for u in staff_before if u.get("employeeId")), sum(1 for u in staff_after if u.get("employeeId"))),
                  ("Contractor with type, sponsor and end date", 0, 1),
                  ("Shared test account enabled", 1, 0)]

    # ---- step 2
    cov_b, cov_a = s2_cov["before"], s2_cov["after"]
    new_groups = [l["target"] for l in s2_log if l["action"] == "create group"]
    held = s2_cov.get("held", [])

    # ---- step 3
    app_rows = [(E(i["app"]), E(", ".join(i["roles"])), "Yes" if i["assignmentRequired"] else "No", i["assignedUsers"]) for i in s3_first["inventory"]]

    # ---- step 4
    def jrow(k):
        r = jml[k]
        b, a = r.get("before") or {}, r["after"]
        return (f"<b>{E(r['ticket'])}</b><br>{E(k.title())}", E(r["summary"]),
                E(", ".join(b.get("groups", [])) or "—"), E(", ".join(a["groups"]) or "—"),
                E(", ".join(x.replace("HVMC ", "") for x in b.get("apps", [])) or "—"), E(", ".join(x.replace("HVMC ", "") for x in a["apps"]) or "—"),
                "Enabled" if a["user"]["accountEnabled"] else "<b>Disabled</b>")
    rem = jml["mover"].get("remediation", {})

    # ---- step 5
    keep = sum(1 for r in ar_items if r["recommendation"] in ("Keep", "Reviewer decides"))
    remove = [r for r in ar_items if r["recommendation"] == "Remove"]
    by_rev = {}
    for r in ar_items:
        by_rev.setdefault(r["reviewer"].split(" (")[0], 0)
        by_rev[r["reviewer"].split(" (")[0]] += 1
    flags = {}
    for r in ar_items:
        flags[r["flag"] or "None (matches RBAC v2)"] = flags.get(r["flag"] or "None (matches RBAC v2)", 0) + 1

    # ---- step 6
    lic = {}
    for p in ca.POLICIES:
        lic.setdefault(p[3], []).append(p[0])
    ca_rows = [(f"<b>{p[0]}</b>", E(p[1].split("-", 1)[1]), E(p[2]), E(p[3]), E(p[4])) for p in ca.POLICIES]

    # ---- step 7
    s7_rows = []
    labels = {"allowInvitesFrom": "Who can invite guests", "guestUserRoleId": "Guest directory access",
              "allowEmailVerifiedUsersToJoinOrganization": "Email-verified self-service sign-up",
              "allowedToSignUpEmailBasedSubscriptions": "Self-service sign-up for subscriptions",
              "allowedToCreateApps": "Users can register applications", "allowedToCreateSecurityGroups": "Users can create security groups",
              "allowedToCreateTenants": "Users can create tenants", "permissionGrantPoliciesAssigned": "User consent to applications"}
    def v7(k, d):
        val = d.get(k, d.get("defaultUserRolePermissions", {}).get(k))
        if k == "permissionGrantPoliciesAssigned":
            return "Do not allow user consent" if not val else "Allowed (" + str(len(val)) + " consent policies)"
        if k == "guestUserRoleId":
            return th.GUEST_ROLE_NAMES.get(val, val)
        if k == "allowInvitesFrom":
            return {"everyone": "Everyone, including guests", "adminsAndGuestInviters": "Admins and Guest Inviter role only"}.get(val, val)
        return "Yes" if val is True else "No" if val is False else str(val)
    for k, lab in labels.items():
        s7_rows.append((E(lab), E(v7(k, s7_before)), f"<b>{E(v7(k, s7_after))}</b>"))
    s7_gas = [("Emergency Access" if a.startswith("bg-") else "Named administrator", a.split("@")[0] + "@&lt;tenant&gt;.onmicrosoft.com" if a.startswith("bg-") else "IAM administrator (Sabitha S Karanavar)") for a in s7_bg["global_admins"]]

    style = open(STYLE).read().replace("<title>HVMC Report</title>", "<title>HVMC IAM Hands-On Entra Operations</title>")
    style = style.replace("</style>", "table.tiny{font-size:7.6pt} table.tiny td,table.tiny th{padding:3px 4px} code{font-family:Menlo,monospace;font-size:7.8pt;background:#eef2f8;padding:0 3px} .big{font-size:20pt;font-weight:bold;color:#1f3864}</style>")
    body = f'''{style}
<div class="runhead">Horizon Valley Medical Center &nbsp;|&nbsp; Healthcare IAM Operations Simulation</div>
<h1>Hands-On Identity Operations in Microsoft Entra ID</h1>
<div class="sub">Identity Hygiene · RBAC v2 · Enterprise Applications · Joiner/Mover/Leaver · Access Review · Conditional Access Design · Tenant Hardening</div>
{kv([("Project Name", "Healthcare IAM Operations Simulation"), ("Organization", "Horizon Valley Medical Center (HVMC)"),
                   ("Environment", "Microsoft Entra ID tenant (Free tier), 33 accounts; changes made with Microsoft Graph via scripted, ticketed changes"),
                   ("Date", "20 October 2026 (Step 7: 28 October 2026)"), ("Document Version", "1.1"), ("Prepared By", "Sabitha S Karanavar"), ("Cost", "$0 — every change used Entra ID Free features")])}

<h2>1. Purpose and approach</h2>
<p>The Week 1 design (scenario, RBAC matrix, OU structure and group naming) was turned into a working, governed identity environment.
Every change followed the same controlled pattern: <b>a script shows a dry run, the change is approved, then applied under a change ticket,
and before/after evidence is saved</b>. Group membership is the single source of truth: application access is derived from groups, so
access always follows the approved design.</p>
{table(["Step", "Work", "Ticket", "Result"], [
    ("1", "Identity hygiene — managers, employee IDs, contractor attributes, disable shared test account", "HVMC-IAM-CHG-101", f"{len(s1_log)} changes"),
    ("2", "RBAC v2 — groups that grant exactly the RBAC matrix", "HVMC-IAM-CHG-102", f"{len(new_groups)} groups, {sum(l['action'] == 'add member' for l in s2_log)} memberships"),
    ("3", "Simulated enterprise applications with app roles", "HVMC-IAM-CHG-103", f"{len(s3_first['inventory'])} apps, {sum(i['assignedUsers'] for i in s3_first['inventory'])} assignments"),
    ("4", "Joiner, mover and leaver", "HVMC-JML-201/202/203", "3 lifecycle events + 1 finding fixed"),
    ("5", "Quarterly access review", "HVMC-AR-2026-Q4", f"{len(ar_items)} lines reviewed, {len(remove)} removal"),
    ("6", "Conditional Access design (report-only, licence-gated)", "—", f"{len(ca.POLICIES)} policies, {len(tests)} test cases"),
    ("7", "Free tenant hardening — consent, guests, self-service; break-glass administrators", "HVMC-IAM-CHG-106/107", f"{len(s7_rows)} settings, Global Admins 1 → {len(s7_gas)}")])}

<h2>2. Starting baseline (findings)</h2>
{table(["#", "Finding", "Why it mattered", "Fixed in"], [
    ("F1", "No user had a manager", "Access reviews and lifecycle approvals need an accountable manager", "Step 1"),
    ("F2", "No employee IDs", "No link between an account and an HR record (risk R06)", "Step 1"),
    ("F3", "One group per department", "Secondary access in the RBAC matrix (e.g. doctors reading Pharmacy and LIS) was not grantable", "Step 2"),
    ("F4", "Shared test account “Test Nurse - EHR” enabled", "Shared account with ePHI access (risk R07)", "Steps 1 and 5"),
    ("F5", "Contractor without type, sponsor or end date", "Contractor access outlives the contract (risk R06)", "Steps 1 and 4"),
    ("F6", "Single Global Administrator", "No backup or emergency access (risk R04)", "Step 7"),
    ("F7", "Permissive tenant defaults: user app consent, anyone can invite guests", "Consent phishing and uncontrolled external access (risk R08)", "Step 7")])}

<h2 class="pb">3. Step 1 — Identity hygiene</h2>
<p>Each department lead became the manager of the department; every staff member received an immutable employee ID
(<code>HVMC-&lt;department code&gt;&lt;sequence&gt;</code>); the contractor was typed, sponsored and given an end date; the shared test
account was disabled. The administrator’s own account was excluded from automated changes.</p>
{table(["Department", "Manager (lead)", "Reports", "Employee IDs"], org_rows, "tiny")}
{table(["Measure", "Before", "After"], s1_metrics)}
<p class="note">Contractor Carlos Diaz: employee ID HVMC-C001, type Contractor, sponsor Kevin O’Brien, contract end 31 Dec 2026 (stored in employeeLeaveDateTime).</p>

<h2>4. Step 2 — RBAC v2</h2>
<p>New groups follow the Week 1 convention <code>SG-&lt;Department&gt;-&lt;Application&gt;-&lt;Access&gt;</code>, one per entitlement in the matrix.
A coverage check compares every user’s groups with the matrix for their department.</p>
{table(["Measure", "Before", "After"], [
    ("Users whose groups exactly match the RBAC matrix", f"{sum(not r['missing'] for r in cov_b)}/{len(cov_b)}", f"{sum(not r['missing'] for r in cov_a)}/{len(cov_a)}"),
    ("Missing entitlements", sum(len(r["missing"]) for r in cov_b), sum(len(r["missing"]) for r in cov_a)),
    ("Access beyond the matrix", sum(len(r["extra"]) for r in cov_b), sum(len(r["extra"]) for r in cov_a)),
    ("SG-* security groups", 10, 10 + len(new_groups))])}
<p><b>New groups:</b> {E(", ".join(new_groups))}.</p>
<h3>Design decisions (RBAC v2 improves on the Week 1 matrix)</h3>
{table(["Entitlement held back", "Decision and reason"], [(E(h["group"]), E(h["reason"])) for h in held])}

<h2 class="pb">5. Step 3 — Simulated enterprise applications</h2>
<p>Each business application from the Week 1 list exists as an app registration and enterprise application with <b>app roles</b> for its
access levels, <b>assignment required</b> (unassigned users are refused), <b>no secrets or API permissions</b>, and a homepage on the reserved
<code>.example</code> domain. Entra ID Free cannot assign <i>groups</i> to applications, so a sync script derives <i>user</i> assignments from
group membership — adding missing ones and removing stale ones — which keeps groups the single source of truth.</p>
{table(["Application", "App roles", "Assignment required", "Users"], app_rows)}

<h2>6. Step 4 — Joiner, mover, leaver</h2>
<p>Group membership is derived from the RBAC v2 matrix; the application sync then follows automatically.</p>
{table(["Ticket", "Event", "Groups before", "Groups after", "Apps before", "Apps after", "Account"], [jrow(k) for k in ("joiner", "mover", "leaver")], "tiny")}
<div class="box"><b>Finding F-JML-01:</b> {E(rem.get("finding", ""))}. <b>Action:</b> {E(rem.get("action", ""))}.
The joiner’s initial password was random, never displayed or stored, with a forced change at first sign-in; the leaver was disabled and all
sign-in sessions revoked before groups were removed, and the account kept (disabled) for audit.</div>

<h2 class="pb">7. Step 5 — Access review HVMC-AR-2026-Q4</h2>
<p>Scope: every SG-* membership (which drives application access), direct application assignments, directory roles, Azure RBAC roles and
disabled accounts. Reviewers: each user’s manager; privileged roles and workload identities: the Security Supervisor; department leads and
admin/test accounts: the IAM administrator. HIPAA 45 CFR 164.308(a)(3)(ii)(B)–(C) and (a)(4)(ii)(C).</p>
<div style="display:flex;gap:12px"><div class="box" style="flex:1"><div class="big">{len(ar_items)}</div>review lines</div>
<div class="box" style="flex:1"><div class="big">{keep}</div>kept with justification</div>
<div class="box" style="flex:1"><div class="big">{len(remove)}</div>removed</div>
<div class="box" style="flex:1"><div class="big">{len(by_rev)}</div>reviewers</div></div>
{table(["Flag", "Lines"], [(E(k), v) for k, v in sorted(flags.items(), key=lambda x: -x[1])])}
{table(["Finding", "Decision"], [
    ("Disabled shared test account still held Azure role HVMC-Nurse-EHR-ReadOnly on the ePHI storage account — disabling an account does not remove its roles", "Removed (reviewer: Security Supervisor)"),
    ("Legacy app EHR-Simulated (created 12 Oct) assigned per user, outside group control", "Brought under group-driven sync from SG-Doctors-EHR-RW and SG-Nursing-EHR-RW; existing assignments kept for continuity of earlier evidence"),
    ("Single Global Administrator", "Kept; action: two break-glass accounts (done in Step 7)"),
    ("Microsoft service identities created by Defender/Sentinel onboarding", "Kept (platform-managed)")])}
<p class="note">Actions log: {E("; ".join(f"{l.get('user', '')} {l.get('access', '')} → {l['result']}" if 'user' in l else f"{l['action']} → {l['result']}" for l in ar_log["removals"]))}.</p>

<h2 class="pb">8. Step 6 — Conditional Access design</h2>
<p>The tenant runs <b>security defaults</b> (confirmed by an AADSTS530035 block on 14 Oct 2026). Conditional Access needs Entra ID P1 (risk policies P2),
so the policy set was designed and generated as deployable Microsoft Graph files in report-only state; the deployment script refuses to run
without a licence. Full detail: <i>HVMC_Conditional_Access_Design.pdf</i>.</p>
{table(["ID", "Policy", "Persona", "Licence", "Risks"], ca_rows, "tiny")}
<p><b>Rollout:</b> P2 trial → break-glass accounts and US named location → 14 days report-only → IT pilot → everyone (security defaults off) →
clinical device policies and risk-based policies. Licence needs: {E("; ".join(f"{k}: {len(v)} policies" for k, v in lic.items()))}.</p>

<h2 class="pb">9. Step 7 — Free tenant hardening</h2>
<p>Two open risks from the baseline and the access review were closed with free Entra ID settings, using the same dry-run → approval →
apply → before/after evidence pattern (<code>step7_tenant_hardening/tenant_hardening.py</code>).</p>
<h3>Part A — Tenant settings (HVMC-IAM-CHG-106, risk R08)</h3>
<p>Users could consent to applications themselves — the route used by <b>consent-phishing</b> attacks, where a fake app asks a user for
access to mail or files — register apps, create tenants and groups outside the IAM process, and anyone (even guests) could invite guests.
All of these now go through administrators. The settings were re-read from the tenant after the change to confirm them.</p>
{table(["Setting", "Before", "After"], s7_rows)}
<h3>Part B — Emergency-access (break-glass) accounts (HVMC-IAM-CHG-107, risk R04)</h3>
<p>The tenant had a single Global Administrator: a lost phone, a forgotten password or a locked account would have left nobody able to
administer HVMC’s identities. Microsoft recommends two cloud-only emergency-access accounts. Rather than making a staff member a
permanent Global Administrator — which would break the least-privilege decision D2 — two dedicated accounts were created.</p>
{table(["Global Administrator", "Account"], s7_gas)}
{table(["Control", "Implementation"], [
    ("Cloud-only, on the .onmicrosoft.com domain", "No dependency on a custom domain, federation or on-premises sync"),
    ("Strong secret, never displayed", "40-character random passwords (~250 bits), written only to a local file readable by the owner; transferred to a password manager / sealed envelope, then the file deleted"),
    ("No daily use, no other access", "No licence, no SG-* groups, no application access; job title marks them as emergency-only"),
    ("MFA", "Security defaults remain on, so each account registers MFA at first sign-in (on a separate authenticator)"),
    ("Testing and monitoring", "Sign-in test every quarter; sign-in logs reviewed after each use (Free tier keeps 7 days of sign-in logs)")])}

<h2>10. Results, lessons learned and next steps</h2>
{table(["Outcome", "Evidence"], [
    ("Every active staff member’s access matches the approved RBAC v2 design (30/30), with no excess access", "Step 2 coverage check, re-run after Steps 4–5"),
    ("Application access is group-driven and self-correcting, including the legacy EHR app", "Step 3 sync: 0 additions / 0 removals pending"),
    ("Joiners, movers and leavers are repeatable, ticketed and evidenced", "HVMC-JML-201/202/203 evidence files"),
    ("Quarterly access review produced decisions, justifications and a removal", "HVMC-AR-2026-Q4 decided review pack (Excel)"),
    ("Zero Trust sign-in policy ready to deploy when licensed", "13 report-only policy files + 13 test cases"),
    ("Tenant defaults hardened and the single-admin risk removed (R04, R08 closed)", "Step 7 before/after policy evidence; 3 Global Administrators")])}
<h3>Lessons learned</h3>
<ul><li><b>Disabling is not deprovisioning:</b> a disabled account kept an Azure data role until the access review removed it.</li>
<li><b>Unmanaged apps defeat good group design:</b> a direct-assigned legacy app kept a transferred nurse’s EHR access (F-JML-01).</li>
<li><b>Licences shape the design:</b> on the Free tier, group-to-app assignment and Conditional Access are unavailable, so automation and
documented design fill the gap until a licence is justified.</li>
<li><b>Least privilege needs judgement:</b> following the Week 1 matrix literally would have given IT standing ePHI access; RBAC v2 records why it does not.</li></ul>
<h3>Next steps</h3>
{table(["Action", "Cost", "Risk"], [
    ("Register MFA on both break-glass accounts and schedule the quarterly sign-in test", "$0", "R04"),
    ("Start the 30-day P2 trial; deploy the 13 policies in report-only; then PIM and native access reviews", "$0 (trial)", "R04, R12"),
    ("Domain controller hvmc-dc01 (HVMC.LAN) is built: join client HVMC-CLIENT01 and mirror the 31 identities by script", "$0", "—")])}

<h2>Appendix — change register and files</h2>
{table(["Ticket", "Date", "Description"], [
    ("HVMC-IAM-CHG-101", "20 Oct 2026", f"Identity hygiene, {len(s1_log)} attribute/manager/account changes"),
    ("HVMC-IAM-CHG-102", "20 Oct 2026", f"RBAC v2, {len(s2_log)} group/membership/description changes"),
    ("HVMC-IAM-CHG-103", "20 Oct 2026", f"Enterprise applications, {len(s3_first['log'])} app/assignment changes"),
    ("HVMC-JML-201/202/203", "20 Oct 2026", "Joiner Olivia Bennett, mover Noah Fischer, leaver Carlos Diaz"),
    ("HVMC-AR-2026-Q4", "20 Oct 2026", "Access review: 94 lines, 1 removal, legacy app brought under management"),
    ("HVMC-IAM-CHG-106", "28 Oct 2026", "Tenant settings: user consent, app registration, tenant and group creation, guest invitations and access, self-service sign-up"),
    ("HVMC-IAM-CHG-107", "28 Oct 2026", "Two emergency-access (break-glass) Global Administrator accounts")], "tiny")}
<p class="note">Scripts: step1_identity_hygiene/identity_hygiene.py · step2_rbac_v2/rbac_v2.py · step3_enterprise_apps/enterprise_apps.py ·
step4_jml/jml.py · step5_access_review/build_review_pack.py, apply_decisions.py · step6_conditional_access/ca_design.py, deploy_ca.py ·
step7_tenant_hardening/tenant_hardening.py.
Each runs as a dry run by default and changes nothing without --apply.</p>
<div class="foot">Horizon Valley Medical Center · Healthcare IAM Operations Simulation · Hands-on Entra ID operations · Sabitha S Karanavar</div>
</body></html>'''
    out = os.path.join(HERE, "HVMC_IAM_Hands_On_Entra_Operations.html")
    open(out, "w").write(body)
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={OUT_PDF}", "file://" + out],
                   capture_output=True, check=True)
    print(OUT_PDF)


if __name__ == "__main__":
    build()
