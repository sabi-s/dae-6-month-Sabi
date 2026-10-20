"""HVMC Conditional Access Design -> PDF (from the step 6 specification in ca_design.py)."""
import html
import importlib.util
import os
import subprocess

E = html.escape
HERE = os.path.dirname(os.path.abspath(__file__))
STYLE = os.path.join(os.path.dirname(HERE), "report_style.html")
STEP6 = os.path.expanduser("~/Downloads/HVMC_IAM_Entra_Handson/step6_conditional_access")
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
spec = importlib.util.spec_from_file_location("ca", os.path.join(STEP6, "ca_design.py"))
ca = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ca)


def who(users):
    if "includeRoles" in users:
        return f"{len(users['includeRoles'])} admin roles"
    if "includeGroups" in users:
        return ", ".join(users["includeGroups"])
    return "All users"


def apps(a):
    if "includeUserActions" in a:
        return "User action: register security info"
    inc = ", ".join(x.replace("HVMC ", "") if x != ca.AZURE_MGMT else "Azure management" for x in a.get("includeApplications", []))
    exc = a.get("excludeApplications")
    return inc + (f"; except {', '.join(x.replace('HVMC ', '') for x in exc)}" if exc else "")


def cond(c):
    out = []
    if "clientAppTypes" in c:
        out.append("Legacy clients")
    if "locations" in c:
        out.append("Outside US")
    if "userRiskLevels" in c:
        out.append("User risk high")
    if "signInRiskLevels" in c:
        out.append("Sign-in risk medium/high")
    if "authenticationFlows" in c:
        out.append("Device-code / auth transfer")
    if "devices" in c:
        out.append("Non-compliant device")
    return ", ".join(out) or "Any"


def grant(g):
    if not g:
        return "— (session only)"
    if "authenticationStrength" in g:
        return "Phishing-resistant MFA"
    names = {"block": "Block", "mfa": "MFA", "compliantDevice": "Compliant device", "passwordChange": "Password change"}
    return f" {g['operator']} ".join(names[x] for x in g["builtInControls"])


def session(s):
    if not s:
        return "—"
    out = []
    f = s.get("signInFrequency")
    if f:
        out.append("Every sign-in" if f.get("frequencyInterval") == "everyTime" else f"Re-auth {f['value']} h")
    if s.get("persistentBrowser"):
        out.append("No persistent browser")
    return ", ".join(out)


def build():
    style = open(STYLE).read().replace("<title>HVMC Report</title>", "<title>HVMC Conditional Access Design</title>")
    style = style.replace("</style>", "table.tiny{font-size:7.6pt} table.tiny td,table.tiny th{padding:3px 4px} code{font-family:Menlo,monospace;font-size:7.8pt;background:#eef2f8;padding:0 3px}</style>")
    pol = "".join(f"<tr><td><b>{p[0]}</b></td><td>{E(p[1])}</td><td>{E(who(p[6]))}</td><td>{E(apps(p[7]))}</td><td>{E(cond(p[8]))}</td>"
                  f"<td>{E(grant(p[9]))}</td><td>{E(session(p[10]))}</td><td>{E(p[3])}</td><td>{E(p[4])}</td></tr>" for p in ca.POLICIES)
    why = "".join(f"<tr><td><b>{p[0]}</b></td><td>{E(p[2])}</td><td>{E(p[5])}</td></tr>" for p in ca.POLICIES)
    tests = "".join("<tr>" + "".join(f"<td>{E(x)}</td>" for x in t) + "</tr>" for t in ca.TEST_PLAN)
    body = f'''{style}
<div class="runhead">Horizon Valley Medical Center &nbsp;|&nbsp; Healthcare IAM Operations Simulation</div>
<h1>Conditional Access Design</h1>
<div class="sub">Zero Trust sign-in policy for the HVMC Entra ID tenant · Hands-on Step 6</div>
<div class="tag">Prepared by Sabitha S Karanavar · 20 October 2026 · Version 1.0 · Status: design approved for report-only deployment</div>

<h2>1. Purpose and current state</h2>
<p>Conditional Access (CA) decides, at every sign-in, whether access is allowed, needs more proof (MFA, a managed device) or is
blocked, based on who is signing in, to which app, from where and with what risk. This document designs the CA policy set for HVMC
on top of the identity work already done: department managers and employee IDs (Step 1), RBAC v2 groups (Step 2), ten enterprise
applications (Step 3), joiner/mover/leaver (Step 4) and access review HVMC-AR-2026-Q4 (Step 5).</p>
<table class="kv"><tr><td>Licence</td><td>Entra ID Free — CA requires P1; risk-based policies require P2. Design only for now; the 13 policies are generated as
deployable report-only Graph files (<code>policies/</code>) and <code>deploy_ca.py</code> refuses to apply without a licence.</td></tr>
<tr><td>Current protection</td><td><b>Security defaults ON</b> (confirmed: a device-code sign-in was blocked with AADSTS530035 on 14 Oct 2026): MFA registration for all,
MFA for admins, legacy authentication blocked. Good baseline, but all-or-nothing: no per-app, per-device or per-group rules.</td></tr>
<tr><td>Existing CA policies</td><td>0</td></tr>
<tr><td>Related open settings</td><td>Users can register apps and consent to app permissions; anyone can invite guests (risk R08) — see section 7.</td></tr></table>

<h2>2. Design principles</h2>
<ul>
<li><b>Persona-based:</b> policies target personas (everyone, administrators, clinical users of ePHI apps, contractors), not individuals.</li>
<li><b>Naming:</b> <code>CA###-Persona-Apps-Control</code>, so the policy list reads as documentation.</li>
<li><b>Break-glass excluded from every policy:</b> two cloud-only emergency accounts with FIDO2 keys in group <code>SG-CA-Exclude-BreakGlass</code>, monitored by a Sentinel alert on any use (this also closes the open R04 action from the access review).</li>
<li><b>Report-only first:</b> every policy starts in <code>enabledForReportingButNotEnforced</code>; nobody is locked out by a design mistake.</li>
<li><b>Least privilege continues at sign-in:</b> RBAC decides <i>what</i> a person may use; CA decides <i>under which conditions</i>.</li>
</ul>

<h2 class="pb">3. Policy set</h2>
<table class="tiny"><tr><th>ID</th><th>Policy</th><th>Users</th><th>Apps</th><th>Condition</th><th>Grant</th><th>Session</th><th>Licence</th><th>Risks</th></tr>{pol}</table>
<h3>Why each policy exists</h3>
<table class="tiny"><tr><th>ID</th><th>Persona</th><th>Reason</th></tr>{why}</table>

<h2 class="pb">4. Break-glass (emergency access) accounts</h2>
<table class="kv"><tr><td>Accounts</td><td>2 cloud-only accounts on the .onmicrosoft.com domain, Global Administrator, not tied to any person or device</td></tr>
<tr><td>Authentication</td><td>FIDO2 security keys held in two separate locked locations (IT Manager, Security Supervisor)</td></tr>
<tr><td>Policy scope</td><td>Excluded from every CA policy through <code>SG-CA-Exclude-BreakGlass</code>; the group itself is reviewed every quarter</td></tr>
<tr><td>Monitoring</td><td>Sentinel analytics rule: any sign-in by a break-glass account raises a High incident and e-mails the Security Lead</td></tr>
<tr><td>Testing</td><td>Sign-in tested every 90 days and after every CA change; result recorded</td></tr></table>

<h2>5. Test plan (What-If tool and sign-in logs)</h2>
<table class="tiny"><tr><th>ID</th><th>Persona</th><th>App</th><th>Scenario</th><th>Policies</th><th>Expected result</th></tr>{tests}</table>

<h2 class="pb">6. Rollout plan</h2>
<table><tr><th>Phase</th><th>Action</th><th>Exit criterion</th></tr>
<tr><td><b>0 · Prepare</b></td><td>Start the free 30-day Entra ID P2 trial; create the break-glass accounts and group, the US named location; register passkeys for admins</td><td>Break-glass sign-in tested</td></tr>
<tr><td><b>1 · Report-only (14 days)</b></td><td><code>deploy_ca.py --apply</code> creates all 13 policies in report-only; review the CA insights and sign-in logs daily</td><td>No unexpected "would block" results for normal work</td></tr>
<tr><td><b>2 · Pilot ring</b></td><td>Enable CA001–CA004, CA010, CA011 for the IT group</td><td>One week without helpdesk issues</td></tr>
<tr><td><b>3 · Everyone</b></td><td>Enable the baseline for all users; <b>turn security defaults OFF</b> at the same moment (they cannot coexist with CA)</td><td>All test cases T01–T13 pass</td></tr>
<tr><td><b>4 · Clinical and contractors</b></td><td>Enable CA005–CA009 once devices are enrolled (Intune); then risk policies CA012–CA013</td><td>Monthly review of CA insights</td></tr></table>

<h2>7. Complementary tenant settings (free, no CA licence needed)</h2>
<table><tr><th>Setting</th><th>Today</th><th>Recommended</th><th>Risk</th></tr>
<tr><td>User consent to apps</td><td>Allowed</td><td>Only for verified publishers and low-risk permissions; admin-consent workflow for the rest</td><td>R08</td></tr>
<tr><td>Users can register applications</td><td>Yes</td><td>No — only Application Administrators</td><td>R08</td></tr>
<tr><td>Guest invitations</td><td>Anyone</td><td>Only admins and the Guest Inviter role</td><td>R08</td></tr>
<tr><td>Global Administrators</td><td>1</td><td>2 named admins + 2 break-glass, others use least-privileged roles</td><td>R04</td></tr></table>
<div class="foot">Horizon Valley Medical Center · Conditional Access Design v1.0 · Sabitha S Karanavar</div>
</body></html>'''
    out = os.path.join(HERE, "HVMC_Conditional_Access_Design.html")
    open(out, "w").write(body)
    pdf = os.path.join(STEP6, "HVMC_Conditional_Access_Design.pdf")
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={pdf}", "file://" + out], capture_output=True, check=True)
    print(pdf)


if __name__ == "__main__":
    build()
