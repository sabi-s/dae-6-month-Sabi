"""Build HVMC_Step10_MFA_Support_Run_2026-11-05.pdf - what was done in Step 10 (Activity 4, ticket IAM-0004) so far.

Uses the real screenshots in ticket/screenshots/ and the evidence JSON in evidence/ (no tenant identifiers).
"""
import base64
import glob
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.expanduser("~/Downloads/HVMC_Crypto_Reports"))
from report_common import CSS, table  # noqa: E402

SHOTS = os.path.join(HERE, "ticket", "screenshots")
EVID = os.path.join(HERE, "evidence")
OUT_HTML = os.path.join(HERE, "HVMC_Step10_MFA_Support_Run_2026-11-05.html")
OUT_PDF = os.path.join(HERE, "HVMC_Step10_MFA_Support_Run_2026-11-05.pdf")
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
DONE, TODO = "✅ Done", "⏳ Next"

fig_no = [0]


def fig(name, caption):
    fig_no[0] += 1
    data = base64.b64encode(open(os.path.join(SHOTS, name), "rb").read()).decode()
    return (f'<figure><img src="data:image/png;base64,{data}">'
            f'<figcaption>Figure {fig_no[0]}. {caption}</figcaption></figure>')


reset = json.load(open(sorted(glob.glob(os.path.join(EVID, "*_mfa_reset.json")))[-1]))
results = "".join(f"<tr><td>{r['time']} UTC</td><td>{r['step']}</td><td>{r['result']}</td></tr>" for r in reset["results"])

EXTRA_CSS = """
figure { margin:10px 0 16px; break-inside:avoid; text-align:center; }
figure img { max-width:100%; border:1px solid #c9d3e3; }
figcaption { font-size:8.8pt; color:#444; font-style:italic; margin-top:4px; }
"""

body = f"""
<div class="runhead">Horizon Valley Medical Center &nbsp;|&nbsp; Healthcare IAM Operations Simulation</div>
<h1>Step 10: MFA Support for a Lost Phone</h1>
<div class="sub">Board Activity 4 · Ticket IAM-0004 · Completed 5 November 2026</div>
<div class="tag">Dr. Sarah Chen (HVMC-1001, Doctors) lost the phone with her Microsoft Authenticator app. The help desk revoked
her sessions and removed the lost phone's MFA method so she can register a new phone.</div>
<table class="meta"><tbody>
<tr><td>Prepared By</td><td>Sabitha S Karanavar</td></tr>
<tr><td>Date</td><td>November 5, 2026</td></tr>
<tr><td>Ticket</td><td>IAM-0004 — MFA support, lost device</td></tr>
<tr><td>Tool</td><td>Invoke-HvmcMfaSupport.ps1 (PowerShell 7, Microsoft Graph), actions Status / Reset / Verify</td></tr>
<tr><td>Performed by</td><td>helpdesk.admin (roles: Authentication Administrator + Reports Reader), not the Global Admin</td></tr>
<tr><td>Cost</td><td>$0 (Microsoft Entra ID Free)</td></tr>
</tbody></table>

<h2>Summary</h2>
{table(["Step", "What", "Status"], [
    ["0", "Set-up: Sarah registered Microsoft Authenticator (her “old phone”)", DONE + " (4 Nov)"],
    ["1", "Status before the reset", DONE],
    ["2", "Verify the caller: call-back to the phone number HR has on file", DONE],
    ["3", "Dry run of the reset (nothing changed)", DONE],
    ["4", "Reset: revoke all sessions, remove the lost phone's Authenticator", DONE],
    ["5", "Sarah registers her new phone (3:52 PM)", DONE],
    ["6", "Verify: 6 automatic checks — 6/6 passed (3:54 PM)", DONE],
    ["7", "Audit log in the Entra portal", DONE],
], ["8%", "70%", "22%"])}

<h2>1. Getting the help-desk tool to sign in</h2>
<p>The script needs the Microsoft Graph permission to manage authentication methods, which needs an interactive sign-in.
Three problems came up before it worked. Each one taught something about identity security:</p>
{table(["#", "Problem", "Cause", "Fix"], [
    ["1", "Script said <i>No account with employee ID HVMC-1001</i>",
     "The browser sign-in had not finished; the script carried on without a connection and showed a misleading error",
     "Script now stops with a clear message if it is not signed in or a permission is missing"],
    ["2", "<i>You don't have access to this</i>",
     "The Global Admin is a personal Microsoft account (gmail). Without the tenant named, sign-in went to the wrong directory",
     "Script signs in to the HVMC tenant by name (ID read at run time, never stored in the file)"],
    ["3", "Error <b>AADSTS530035</b>: access blocked by <b>security defaults</b>",
     "Security defaults block the personal-account Global Admin from Microsoft Graph PowerShell",
     "Kept security defaults ON. Created a dedicated help-desk account inside the tenant (next section)"],
], ["5%", "25%", "35%", "35%"])}

<h2>2. Least privilege: a dedicated help-desk account</h2>
<p>Instead of weakening security defaults or using the Global Admin for routine work, a help-desk account was created,
the way a real hospital help desk is set up:</p>
{table(["Item", "Setting", "Why"], [
    ["Account", "HVMC Help Desk Admin (helpdesk.admin@&lt;tenant&gt;), IT, HVMC-ADM-01", "Separate admin identity for help-desk work"],
    ["Role 1", "<b>Authentication Administrator</b>", "Can reset MFA and revoke sessions for <b>normal users only</b>, never for admins"],
    ["Role 2", "<b>Reports Reader</b>", "Can read the audit logs needed for the Verify step"],
    ["MFA", "Its own Microsoft Authenticator", "Required by security defaults; every admin sign-in uses MFA"],
    ["App approval", "Microsoft Graph Command Line Tools approved for <b>helpdesk.admin only</b> (consent type: Principal)",
     "Users cannot approve apps themselves (Step 7 hardening), so the Global Admin approved it for this one account"],
    ["Initial password", "Random, stored in a private file, changed at first sign-in, file deleted", "Never shown on screen or in chat"],
], ["16%", "46%", "38%"])}
<div class="box">The Global Admin is now only used to set things up. The day-to-day MFA reset was done by an account that
<b>cannot</b> change admins, roles or other settings, which is separation of duties and least privilege.</div>

<h2>3. Step 1: status before the reset</h2>
<p>Signed in as helpdesk.admin. Sarah's account is enabled and has one MFA method: Microsoft Authenticator on an iPhone 12 Pro
(the phone reported lost). The audit history shows her registration on 4 November.</p>
{fig("01_status_before.png", "Status before the reset: 2 registered methods (Password + Microsoft Authenticator), MFA methods: 1.")}

<h2>4. Steps 2 and 3: verify the caller, then a dry run</h2>
<p><b>Step 2 — identity check (most important).</b> Before any reset, the help desk confirms the caller really is Sarah:
<i>call-back to the phone number HR has on file</i>. An attacker who calls pretending to be a doctor who “lost their phone”
is a common way to take over accounts (help-desk social engineering), so this check is required: the script refuses
<code>-Apply</code> without <code>-VerifiedBy</code>.</p>
<p><b>Step 3 — dry run.</b> The script shows exactly what it would do and changes nothing:</p>
{fig("02_reset_dryrun.png", "Dry run: 1) revoke all sign-in sessions, 2) remove the Authenticator on the lost iPhone; password and reset e-mail kept.")}

<h2>5. Step 4: the reset</h2>
<p>Run with <code>-Apply -VerifiedBy "Call-back to the phone number HR has on file"</code>:</p>
<table><thead><tr><th>Time</th><th>Step</th><th>Result</th></tr></thead><tbody>{results}</tbody></table>
{fig("03_reset_apply.png", "Reset applied: both steps returned ok. The re-check 3 seconds later still listed the method (see below).")}
<div class="box warn"><b>Finding: directory replication delay.</b> Both steps returned <b>ok</b>, but the script's own re-check
3 seconds later still listed the Authenticator and printed “RESET INCOMPLETE”. Entra ID can show a deleted method for a short
time. A Status check two minutes later confirmed the method was gone. The script was improved: it now waits up to 2 minutes
for the change to appear, and only says “incomplete” when a step really failed.</div>
{fig("03b_status_after_reset.png", "Status after the reset: Registered methods (1): Password, MFA methods: 0. New audit events at 20:27 by helpdesk.admin: refresh tokens revoked (StsRefreshTokenValidFrom) and the user updated.")}

<h2>6. What the reset did and did not change</h2>
{table(["Changed", "Not changed"], [
    ["All sign-in sessions revoked on every device, including the lost phone", "Password (Sarah did not lose it)"],
    ["Microsoft Authenticator on the lost iPhone removed", "Password-reset e-mail"],
    ["Sarah must register a new MFA method at her next sign-in", "Groups, app access, account enabled"],
], ["50%", "50%"])}

<h2>7. Step 5: Sarah registers her new phone</h2>
<p>Sarah signed in with her password only (no MFA method was left), was asked to register, and added Microsoft Authenticator
on the new phone herself. The help desk never handled her credentials.</p>
{fig("04_reregister.png", "Sarah's Security info page after re-registration: Password and Microsoft Authenticator (push MFA).")}
<div class="box warn"><b>Lab note.</b> During the lab, Sarah's password was reset by the IAM admin (3:49 and 3:51 PM) because the
test password was not at hand, then changed by Sarah. In a real lost-phone case the password is not touched; it is not part of
the MFA reset.</div>

<h2>8. Step 6: Verify — 6/6 checks passed</h2>
{fig("05_verify.png", "Verify run at 3:54 PM: all 6 checks passed, including “Admin deleted security info” by helpdesk.admin and “User registered security info” by Sarah.")}

<h2>9. Step 7: audit log in the Entra admin center</h2>
{fig("06a_audit_admin_deleted.png", "“Admin deleted security info” (Microsoft Authenticator) at 3:27 PM, initiated by HVMC Help Desk Admin, not the Global Admin.")}
{fig("06b_audit_registered.png", "“User registered security info” by Sarah Chen: the old phone on 4 Nov and the new phone on 5 Nov at 3:52 PM.")}

<h2>10. Result</h2>
{table(["Item", "Result"], [
    ["Ticket", "IAM-0004 opened 3:25 PM, closed 3:54 PM (29 minutes), see Ticket_IAM-0004_MFA_Support.pdf"],
    ["Lost phone", "Signed out everywhere and its Authenticator removed"],
    ["User", "Back in with MFA on the new phone; password, groups and apps unchanged by the MFA reset"],
    ["Who did it", "helpdesk.admin (Authentication Administrator + Reports Reader), with the caller's identity checked first"],
    ["Evidence", "Script evidence JSON, 9 screenshots, Entra audit log (Admin deleted / User registered security info)"],
], ["22%", "78%"])}
"""

page = f"""<!doctype html><html><head><meta charset="utf-8"><title>HVMC Step 10 MFA Support Run 2026-11-05</title>
<style>{CSS}{EXTRA_CSS}</style></head><body>{body}</body></html>"""
with open(OUT_HTML, "w") as f:
    f.write(page)
subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={OUT_PDF}",
                "file://" + OUT_HTML], capture_output=True, check=True)
print("wrote", OUT_PDF)
