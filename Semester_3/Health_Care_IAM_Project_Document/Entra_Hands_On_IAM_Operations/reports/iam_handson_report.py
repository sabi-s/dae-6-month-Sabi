"""HVMC Healthcare IAM - hands-on Entra ID operations (Steps 1-9, 8b) deliverable -> PDF, built from the evidence files."""
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
    nhi_reg = json.load(open(os.path.join(ROOT, "step8_nonhuman_identities/nhi_register.json")))[0]
    nhi_test = latest("step8_nonhuman_identities/evidence/*_nhi_test.json")
    nhi_inv = first("step8_nonhuman_identities/evidence/*_nhi_inventory_before.json")
    pr = latest("step9_credential_cleanup/evidence/*_password_reset.json")
    lc_dir = os.path.join(ROOT, "step8b_lifecycle_automation/evidence")
    lc_runs = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(lc_dir, "*_lifecycle_run.json")))]
    lc_first = lc_runs[0]                                   # 2 Nov 13:46 - the three events
    lc_done = [e for r in lc_runs for e in r["events"] if e["status"] == "Done"]
    lc_lv = latest("step8b_lifecycle_automation/evidence/*_leaver_check.json")
    lc_lv_act = lc_lv["actions"][0]
    lc_steps = sum(len(e["results"]) for e in lc_done) + len(lc_lv_act["results"])
    lc_ok = sum(r["result"] == "ok" for e in lc_done for r in e["results"]) + sum(r["result"] == "ok" for r in lc_lv_act["results"])
    lc_now = {u["employeeId"]: u for u in latest("step8b_lifecycle_automation/evidence/*_lifecycle_verification.json")["users"]}
    lc_rerun = open(os.path.join(lc_dir, "20261102_rerun_dryrun.txt")).read()
    lc_after = open(os.path.join(lc_dir, "20261102_leavercheck_dryrun_after_apply.txt")).read()
    lc_leave = next(e for e in lc_runs[-1]["events"] if e["ticket"] == "HVMC-JML-206")["after"]["employeeLeaveDateTime"]
    lc_lv_time = lc_lv_act["results"][0]["time"][11:16]
    hd = latest("step8b_lifecycle_automation/evidence/*_hire_dates.json")
    lc_rows = []
    for e in (e for e in lc_first["events"] if e["status"] == "Done"):
        before_ = e["before"]
        if e["ticket"] == "HVMC-JML-206":
            a_ = lc_lv_act["after"]
            after_txt = (f"Last day moved by HR to 2 Nov, access ending {lc_leave[11:16]} UTC (end of shift). Removed by the leaver check at {lc_lv_time} UTC: "
                         f"account {'disabled' if not a_['accountEnabled'] else 'ENABLED'}, sessions revoked, groups: {', '.join(a_['groups']) or 'none'}; "
                         f"apps: {', '.join(a_['apps']) or 'none'}")
        else:
            now_ = lc_now[{"HVMC-JML-204": "HVMC-1304", "HVMC-JML-205": "HVMC-1603"}[e["ticket"]]]
            after_txt = f"{now_['department']}; groups: {', '.join(now_['groups'])}; apps: {', '.join(now_['apps'])}"
        lc_rows.append((e["ticket"], E(e["employee"].split(" (")[0]), E(e["event"]),
                        "no account" if not before_ else E(f"{before_['department']}; groups: {', '.join(before_['groups'])}; apps: {', '.join(before_['apps'])}"),
                        E(after_txt)))
    pr_disabled = 1   # Carlos Diaz (HVMC-JML-203) - reset as well, so the old password is useless if the account is re-enabled

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

    s10_dir = os.path.join(ROOT, "step10_mfa_support")
    s10_verify = latest(os.path.join(s10_dir, "evidence", "*_mfa_verify.json"))
    s10_reset = latest(os.path.join(s10_dir, "evidence", "*_mfa_reset.json"))
    s10_pass = sum(1 for v in s10_verify["checks"].values() if v)
    def s10_fig(name, cap):
        import base64
        b = base64.b64encode(open(os.path.join(s10_dir, "ticket", "screenshots", name), "rb").read()).decode()
        return (f'<div style="break-inside:avoid;margin:8px 0 12px;text-align:center"><img style="max-width:100%;border:1px solid #c9d3e3" '
                f'src="data:image/png;base64,{b}"><div style="font-size:8.4pt;font-style:italic;color:#444">{cap}</div></div>')

    style = open(STYLE).read().replace("<title>HVMC Report</title>", "<title>HVMC IAM Hands-On Entra Operations</title>")
    style = style.replace("</style>", "table.tiny{font-size:7.6pt} table.tiny td,table.tiny th{padding:3px 4px} code{font-family:Menlo,monospace;font-size:7.8pt;background:#eef2f8;padding:0 3px} .big{font-size:20pt;font-weight:bold;color:#1f3864}</style>")
    body = f'''{style}
<div class="runhead">Horizon Valley Medical Center &nbsp;|&nbsp; Healthcare IAM Operations Simulation</div>
<h1>Hands-On Identity Operations in Microsoft Entra ID</h1>
<div class="sub">Identity Hygiene · RBAC v2 · Enterprise Applications · Joiner/Mover/Leaver · Access Review · Conditional Access Design · Tenant Hardening · Non-Human Identities · Lifecycle Automation · Credential Clean-up · MFA Support</div>
{kv([("Project Name", "Healthcare IAM Operations Simulation"), ("Organization", "Horizon Valley Medical Center (HVMC)"),
                   ("Environment", "Microsoft Entra ID tenant (Free tier), 36 accounts on 2 Nov 2026; changes made with Microsoft Graph via scripted, ticketed changes"),
                   ("Date", "20 October 2026 (Steps 7–9: 28–29 Oct; Step 8b: 2 Nov; Step 10: 5 Nov 2026)"), ("Document Version", "1.6"), ("Prepared By", "Sabitha S Karanavar"), ("Cost", "$0 — every change used Entra ID Free features")])}

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
    ("7", "Free tenant hardening — consent, guests, self-service; break-glass administrators", "HVMC-IAM-CHG-106/107", f"{len(s7_rows)} settings, Global Admins 1 → {len(s7_gas)}"),
    ("8", "Non-human identity with certificate credential and least-privilege Graph permission", "HVMC-IAM-CHG-108", f"1 NHI, {sum(r['pass'] for r in nhi_test['results'])}/{len(nhi_test['results'])} least-privilege tests passed"),
    ("8b", "Lifecycle automation in PowerShell — HR feed and daily leaver check", "HVMC-JML-204/205/206", f"3 events, {lc_ok}/{lc_steps} steps ok; leaver removed by the daily check"),
    ("9", "Credential clean-up — reset the passwords exposed in the bulk-create file", "HVMC-IAM-CHG-109", f"{pr['reset_ok']}/{pr['reset_ok'] + pr['failed']} passwords reset, plain-text file deleted")])}

<h2>2. Starting baseline (findings)</h2>
{table(["#", "Finding", "Why it mattered", "Fixed in"], [
    ("F1", "No user had a manager", "Access reviews and lifecycle approvals need an accountable manager", "Step 1"),
    ("F2", "No employee IDs", "No link between an account and an HR record (risk R06)", "Step 1"),
    ("F3", "One group per department", "Secondary access in the RBAC matrix (e.g. doctors reading Pharmacy and LIS) was not grantable", "Step 2"),
    ("F4", "Shared test account “Test Nurse - EHR” enabled", "Shared account with ePHI access (risk R07)", "Steps 1 and 5"),
    ("F5", "Contractor without type, sponsor or end date", "Contractor access outlives the contract (risk R06)", "Steps 1 and 4"),
    ("F6", "Single Global Administrator", "No backup or emergency access (risk R04)", "Step 7"),
    ("F7", "Permissive tenant defaults: user app consent, anyone can invite guests", "Consent phishing and uncontrolled external access (risk R08)", "Step 7"),
    ("F8", "No governed pattern for non-human (workload) identities", "Service accounts with shared passwords or broad API permissions are a common breach path", "Step 8"),
    ("F9", "Initial passwords of all staff kept in a plain-text bulk-create file (one shown on screen)", "Anyone who saw or copied the file could sign in as any staff member", "Step 9"),
    ("F10", "Lifecycle changes run by hand, one event at a time; no check that leave dates are acted on", "A leaver whose date passes unnoticed keeps access (risk R06)", "Step 8b"),
    ("F11", "Bulk-created staff accounts had no hire date", "Access reviews and audits cannot see how long access has been held", "Step 8b (CHG-110)")])}

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

<h2 class="pb">10. Step 8 — Non-human identities</h2>
<p>Hospital systems talk to each other without a person signing in: an interface engine, a lab system, a backup job. These
<b>non-human identities (NHIs)</b> often outnumber people and are a common breach path when they use shared passwords, never-expiring
secrets or broad permissions. Step 8 inventoried HVMC’s NHIs and created the first one using the secure pattern
(<code>step8_nonhuman_identities/nhi.py</code>, change HVMC-IAM-CHG-108).</p>
<h3>Baseline inventory (read-only)</h3>
{table(["Category", "Count", "Assessment"], [
    ("User accounts used as service accounts", 0, "None — matches Microsoft guidance to use workload identities instead"),
    ("HVMC application service principals", nhi_inv["own"], "No secrets, certificates or API permissions — cannot authenticate on their own"),
    ("Managed identities", len(nhi_inv["managed_identities"]), "Created by Defender for Storage (SecOps lab); probably orphaned since the subscription was disabled — noted for HVMC-AR-2027-Q1"),
    ("Microsoft / third-party service principals", nhi_inv["microsoft_and_third_party"], "Present in every tenant; no action")])}
<h3>The new NHI: {E(nhi_reg["nhi"])}</h3>
{table(["Control", "Implementation"], [
    ("Purpose and ownership", f"{E(nhi_reg['purpose'])}. Technical owner: {E(nhi_reg['owner'])}; business owner: {E(nhi_reg['business_owner'])}"),
    ("Identity type", "Single-tenant application service principal, tagged HVMC-NHI, ticket in its notes"),
    ("Credential", "X.509 certificate (RSA-2048) issued by <b>HVMC Issuing CA 1</b> from the project’s own PKI; <b>no client secret</b>. Private key kept locally (mode 0600, not in Git), to move into Azure Key Vault"),
    ("Lifetime", f"Expires {nhi_reg['credential_expires']}; rotate by {nhi_reg['rotate_by']}"),
    ("Permission", "Microsoft Graph <b>GroupMember.Read.All</b> (application) only, granted by admin consent"),
    ("Review", f"Recorded in the NHI register; reviewed in {nhi_reg['next_review']}")])}
<p>The NHI then signed in <b>as itself, with its certificate</b> (OAuth 2.0 client credentials with a signed JWT assertion). Its token
carried exactly one permission (<code>{E(", ".join(nhi_test["roles_in_token"]))}</code>) and the identity type “application”.
Three calls proved least privilege:</p>
{table(["Call made by the NHI", "Expected", "Result"], [(E(r["test"]), r["expected"], f"HTTP {r['status']} {E(r['detail'])} — <b>{'PASS' if r['pass'] else 'FAIL'}</b>") for r in nhi_test["results"]])}
<p class="note">Next for NHIs: move the private key into Azure Key Vault and use a managed identity (instructor-approved, needs an
active subscription); a GitHub Actions identity with a federated credential (no secret at all); Workload ID Premium controls
(Conditional Access and risk detection for workload identities) documented as a licensed design.</p>

<h2 class="pb">11. Step 8b — Lifecycle automation in PowerShell</h2>
<p>In Step 4 each joiner, mover and leaver was a separate scripted change, started by hand (finding F10). Step 8b turns this into a
repeatable process driven by the HR system, written in <b>PowerShell 7 with the Microsoft Graph SDK</b> — the standard tooling for
Microsoft identity administration (<code>step8b_lifecycle_automation/</code>).</p>
{table(["Part", "What it does"], [
    ("<b>HR feed</b> (CSV)", "One row per event exported by HR: ticket, Join / Move / Leave, employee ID, department, title, manager, effective date, and an optional end-of-shift time (UTC) for a same-day leaver"),
    ("<b>Invoke-HvmcLifecycle.ps1</b>", "Reads the feed and plans each event from the RBAC v2 matrix (exported to <code>config/rbac_matrix.json</code>, so rbac_v2.py stays the single source of truth); shows the plan, and changes nothing without <code>-Apply</code>"),
    ("<b>Invoke-HvmcLeaverCheck.ps1</b>", "Daily safety net: deprovisions anyone whose leave date has passed (including disabled accounts still in groups), warns 14 days ahead, flags contractors with no end date"),
    ("<b>HVMC.Lifecycle.psm1</b>", "Shared functions: sign-in, desired groups, user state, plans, evidence"),
])}
<h3>Controls built in</h3>
<ul>
<li><b>Dry run first</b>, then <code>-Apply</code>; evidence (plan, results, before/after) saved for every applied run, with no passwords.</li>
<li><b>Safe to re-run:</b> an event already in effect is reported as “already done”; a future date is “not due yet”.</li>
<li><b>Separation of duties on transfer:</b> the old role’s groups are removed <i>before</i> the new role’s are added.</li>
<li><b>Admin accounts are never touched</b>: anyone holding an Entra ID role (the IAM administrator, both break-glass accounts) is excluded.</li>
<li><b>Validation:</b> employee-ID format, known department, existing groups and manager, unique user name — an invalid row is skipped, not guessed.</li>
<li><b>Joiner passwords</b> are random, never shown or stored, and must be changed at first sign-in.</li>
</ul>
<h3>Run of 2 November 2026 (HR feed hr_feed_2026-11-02.csv)</h3>
{table(["Ticket", "Employee", "Event", "Before", "After (including the application sync)"], lc_rows, "tiny")}
<p>All {lc_ok} of {lc_steps} steps succeeded: {sum(len(e["results"]) for e in lc_done)} from the HR feed and {len(lc_lv_act["results"])} from the leaver check,
whose application sync applied {E(lc_lv["appSync"].split(" ")[0])} changes. Jason Park’s IT administration access was removed before he received
the Security portal. HR then moved Victor Mensah’s last day to 2 November, ending at {lc_leave[11:16]} UTC (end of shift). The feed only
recorded the new leave time, and Victor kept his access until then. The IAM administrator ran the daily leaver check at
{lc_lv["checkedAt"][11:16]} UTC, and it removed his sign-in, sessions, groups and applications within five minutes of his shift ending.</p>
<h3>Data fix: hire dates (HVMC-IAM-CHG-110)</h3>
<p>The bulk-created staff accounts had no hire date (finding F11); only staff who came through the joiner process had one.
<code>Set-HvmcHireDates.ps1</code> loaded an HR extract and recorded <b>{hd["verified"]} of {hd["changed"]}</b> hire dates, each re-read to confirm. It
fills empty dates only, never overwrites one (a conflict is referred to HR), and skips admin accounts. The dates are
<b>simulated lab data</b> from a fixed rule: department leads in 2014, later staff by employee-ID order, always a Monday.</p>
<h3>Tests</h3>
{table(["Test", "Result"], [
    ("Re-run the same feed", "All 4 events “already done” (including JML-201 from 20 October); " + E([l for l in lc_rerun.splitlines() if "event(s)" in l][0].strip())),
    ("Leaver check before the leave time", "1 notice for Victor Mensah, nothing changed — access is not removed while someone is still working"),
    ("Leaver check after the leave time (live, -Apply)", f"{sum(r['result'] == 'ok' for r in lc_lv_act['results'])}/{len(lc_lv_act['results'])} steps ok; application sync {E(lc_lv['appSync'].rstrip('.'))}; account disabled, 0 groups, 0 applications"),
    ("Leaver check run again", E([l for l in lc_after.splitlines() if l.startswith("No leavers")][0])),
    ("RBAC coverage after the leaver", "30/30 active staff fully match the matrix; 0 missing, 0 extra; 0 application assignments pending"),
    ("Defect found by testing", "The first run’s evidence took its “after” snapshot before the application sync; fixed, and the post-sync state re-recorded"),
])}
<p class="note">Scheduling: in production the leaver check runs daily as an <b>Azure Automation</b> runbook with a managed identity (no
stored credential) — planned together with Key Vault once a subscription is active. Until then it is run manually by the IAM administrator.</p>

<h2 class="pb">12. Step 9 — Credential clean-up (HVMC-IAM-CHG-109)</h2>
<p>The 30 staff accounts were created in bulk from a CSV file that held every <b>initial password in plain text</b> (finding F9).
One of those passwords had been displayed on screen during an earlier working session. A file like this is a common way
credentials leak: it gets copied, backed up or shared. Step 9 made every password in that file useless
(<code>step9_credential_cleanup/password_reset.py</code>), using the same dry-run → approval → apply → evidence pattern.</p>
{table(["Check", "Result"], [
    ("Dry run", f"{pr['reset_ok'] + pr['failed']} accounts in the file found in Entra ID; 0 hold an admin role (the script stops if one does); {pr_disabled} disabled leaver account"),
    ("Passwords reset", f"<b>{pr['reset_ok']} of {pr['reset_ok'] + pr['failed']}</b>, including the disabled leaver, so the old password is dead if the account is ever re-enabled; {pr['failed']} failures"),
    ("Administrator accounts", "Not touched — the IAM administrator and both break-glass accounts were not in the file"),
    ("New passwords", "16 random characters, all four character classes; generated in memory and <b>never displayed or logged</b>; sent to Graph through a temporary file readable only by the owner, not on the command line"),
    ("Storage", "Written straight into a password-protected archive kept on the administrator’s workstation, outside the repository; archive tested (opens and holds all rows) before anything was deleted" if pr["zip_verified"] else "Archive test failed"),
    ("Old plain-text file", "<b>Deleted</b> after the archive test passed" if pr["old_csv_deleted"] else "Kept — a step failed"),
    ("Evidence", "Who was reset and when, with masked user names and <b>no passwords</b>")])}
<p class="note"><b>Lab trade-offs, recorded on purpose.</b> (1) The new passwords are <i>not</i> forced to change at next sign-in,
so the administrator can keep signing in as test staff; in production each user would get a one-time password or a
<b>Temporary Access Pass</b> and set their own, and passwordless sign-in would remove the shared secret altogether.
(2) The archive uses standard ZIP encryption so it opens on any Mac; it is weak against offline attack, so it never leaves the
workstation. A password manager or an AES-encrypted vault (e.g. Azure Key Vault, once the subscription exists) is the target state.</p>

<h2 class="pb">13. Step 10 — MFA support for a lost phone (ticket IAM-0004)</h2>
<p>Board Activity 4. Dr. Sarah Chen (HVMC-1001) lost the phone holding her Microsoft Authenticator. The help desk checked it was really
her, signed her out everywhere, removed the lost phone’s MFA method, and she registered her new phone herself
(<code>step10_mfa_support/Invoke-HvmcMfaSupport.ps1</code>, actions Status / Reset / Verify).</p>
<h3>Least privilege: a dedicated help-desk account</h3>
<p>The first sign-in attempts with the Global Administrator (a personal Microsoft account) were blocked by <b>security defaults</b>
(AADSTS530035) for Microsoft Graph PowerShell. Security defaults were kept on. Instead, a help-desk account was created inside the tenant:</p>
{table(["Item", "Setting"], [
    ("Account", "HVMC Help Desk Admin (helpdesk.admin@&lt;tenant&gt;), IT, HVMC-ADM-01, its own Microsoft Authenticator"),
    ("Roles", "<b>Authentication Administrator</b> (reset MFA and revoke sessions for non-admin users only) + <b>Reports Reader</b> (audit logs)"),
    ("App approval", "Microsoft Graph Command Line Tools approved for <b>this account only</b> (consent type Principal) — users cannot approve apps themselves since Step 7"),
    ("Effect", "The Global Administrator only set things up; the reset itself was done by an account that cannot change admins, roles or settings")])}
<h3>The run (5 November 2026)</h3>
{table(["Step", "Result"], [
    ("1. Status before", "Sarah enabled; 1 MFA method: Microsoft Authenticator on the lost iPhone"),
    ("2. Identity check", E(s10_reset["identityVerifiedBy"]) + " — required: the script refuses <code>-Apply</code> without <code>-VerifiedBy</code>"),
    ("3. Dry run", "Plan shown: revoke all sessions, remove the Authenticator; password and reset e-mail kept; nothing changed"),
    ("4. Reset (-Apply)", "; ".join(f"{E(r['time'])} UTC {E(r['step'])}: {E(r['result'])}" for r in s10_reset["results"])),
    ("5. New phone", "Sarah signed in with her password and registered Microsoft Authenticator again (3:52 PM local)"),
    ("6. Verify", f"<b>{s10_pass}/{len(s10_verify['checks'])} checks passed</b>, including the audit events below"),
    ("7. Audit log", "“Admin deleted security info” by HVMC Help Desk Admin; “User registered security info” by Sarah Chen")])}
{s10_fig("06a_audit_admin_deleted.png", "Entra audit log: “Admin deleted security info” (Microsoft Authenticator), initiated by HVMC Help Desk Admin — not the Global Administrator.")}
{s10_fig("05_verify.png", "Verify run: 6/6 checks passed after the user registered her new phone.")}
<h3>Findings</h3>
<ul>
<li><b>Replication delay:</b> both reset steps returned ok, but a re-check 3 seconds later still listed the deleted method. The script now waits up
to 2 minutes and only reports “incomplete” when a step really failed; Verify was adjusted to match.</li>
<li><b>Lab note:</b> Sarah’s password was also reset by the IAM administrator during the lab because the test password was not at hand. In a
real lost-phone case the password is not part of the MFA reset.</li>
<li><b>Next improvement:</b> a <b>Temporary Access Pass</b> issued after the identity check would let the user register the new phone without
relying on the password alone.</li>
</ul>
<p class="note">Ticket: <code>step10_mfa_support/ticket/Ticket_IAM-0004_MFA_Support.pdf</code> (opened 3:25 PM, closed 3:54 PM, 9 figures).
Full run log: <code>step10_mfa_support/HVMC_Step10_MFA_Support_Run_2026-11-05.pdf</code>.</p>

<h2>14. Results, lessons learned and next steps</h2>
{table(["Outcome", "Evidence"], [
    ("Every active staff member’s access matches the approved RBAC v2 design (30/30 on 2 Nov), with no excess access", "Step 2 coverage check, re-run after Steps 4–5 and 8b"),
    ("Application access is group-driven and self-correcting, including the legacy EHR app", "Step 3 sync: 0 additions / 0 removals pending"),
    ("Joiners, movers and leavers are repeatable, ticketed and evidenced", "HVMC-JML-201/202/203 evidence files"),
    ("Quarterly access review produced decisions, justifications and a removal", "HVMC-AR-2026-Q4 decided review pack (Excel)"),
    ("Zero Trust sign-in policy ready to deploy when licensed", "13 report-only policy files + 13 test cases"),
    ("Tenant defaults hardened and the single-admin risk removed (R04, R08 closed)", "Step 7 before/after policy evidence; 3 Global Administrators"),
    ("First non-human identity built secret-less and proven least-privilege", "Step 8 certificate sign-in: 1 allowed call, 2 denied calls"),
    ("Joiners, movers and leavers run from an HR feed, with a daily leaver check (F10 closed)", f"Step 8b: {lc_ok}/{lc_steps} steps ok; re-run changes nothing; leaver removed 5 minutes after his shift ended"),
    ("No staff password from the bulk-create file still works (F9 closed)", f"Step 9: {pr['reset_ok']}/{pr['reset_ok'] + pr['failed']} reset, file deleted, evidence without passwords"),
    ("Lost-phone MFA recovery is identity-checked, least-privileged and evidenced", f"Step 10 / IAM-0004: Verify {s10_pass}/{len(s10_verify['checks'])}; reset done by the help-desk account")])}
<h3>Lessons learned</h3>
<ul><li><b>Disabling is not deprovisioning:</b> a disabled account kept an Azure data role until the access review removed it.</li>
<li><b>Unmanaged apps defeat good group design:</b> a direct-assigned legacy app kept a transferred nurse’s EHR access (F-JML-01).</li>
<li><b>Licences shape the design:</b> on the Free tier, group-to-app assignment and Conditional Access are unavailable, so automation and
documented design fill the gap until a licence is justified.</li>
<li><b>Non-human identities need owners and expiry dates:</b> a certificate with a rotate-by date and a named owner is reviewable; a forgotten secret is not.</li>
<li><b>Automation must be safe to run twice:</b> checking the current state first turns a repeated run into “already done” instead of duplicate accounts.</li>
<li><b>Setup files become secrets:</b> a convenience CSV used once to create accounts kept working passwords for every staff member; clean-up is part of the change.</li>
<li><b>The help desk is an attack path:</b> an MFA reset without an identity check hands the account to an attacker; the check is the control, and the help-desk account must not be a Global Administrator.</li>
<li><b>Least privilege needs judgement:</b> following the Week 1 matrix literally would have given IT standing ePHI access; RBAC v2 records why it does not.</li></ul>
<h3>Next steps</h3>
{table(["Action", "Cost", "Risk"], [
    ("Schedule the daily leaver check (Azure Automation runbook with a managed identity)", "Needs an active subscription", "R06"),
    ("Quarterly break-glass sign-in test (next about 28 Jan 2027)", "$0", "R04"),
    ("Azure Key Vault for the NHI private key, plus a managed identity (instructor-approved)", "Needs an active subscription", "NHI"),
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
    ("HVMC-IAM-CHG-107", "28 Oct 2026", "Two emergency-access (break-glass) Global Administrator accounts"),
    ("HVMC-IAM-CHG-108", "29 Oct 2026", "Non-human identity HVMC Lab Results Sync: certificate credential, GroupMember.Read.All, least-privilege test"),
    ("HVMC-JML-204/205/206", "2 Nov 2026", "Step 8b: joiner Ethan Morales, mover Jason Park (IT to Security), leaver Victor Mensah (last day 2 Nov, removed by the leaver check)"),
    ("HVMC-IAM-CHG-110", "2 Nov 2026", f"Hire dates recorded for {hd['verified']} staff accounts from an HR extract (simulated lab data)"),
    ("HVMC-IAM-CHG-109", "29 Oct 2026", f"Credential clean-up: {pr['reset_ok']} staff passwords reset, plain-text bulk-create file deleted"),
    ("IAM-0004", "5 Nov 2026", "MFA support, lost phone (Sarah Chen): help-desk account HVMC Help Desk Admin created (Authentication Administrator + Reports Reader); sessions revoked, Authenticator removed and re-registered; Verify 6/6")], "tiny")}
<p class="note">Scripts: step1_identity_hygiene/identity_hygiene.py · step2_rbac_v2/rbac_v2.py · step3_enterprise_apps/enterprise_apps.py ·
step4_jml/jml.py · step5_access_review/build_review_pack.py, apply_decisions.py · step6_conditional_access/ca_design.py, deploy_ca.py ·
step7_tenant_hardening/tenant_hardening.py · step8_nonhuman_identities/nhi.py · step8b_lifecycle_automation/Invoke-HvmcLifecycle.ps1, Invoke-HvmcLeaverCheck.ps1, Set-HvmcHireDates.ps1 (-Apply) · step9_credential_cleanup/password_reset.py · step10_mfa_support/Invoke-HvmcMfaSupport.ps1 (-Apply -VerifiedBy).
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
