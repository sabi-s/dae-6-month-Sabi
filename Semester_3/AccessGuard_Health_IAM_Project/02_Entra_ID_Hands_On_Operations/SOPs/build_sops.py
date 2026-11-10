"""Build the 4 HVMC IAM Standard Operating Procedures (bullet points, about one page each) as separate PDFs.

SOP-IAM-01 Create account · SOP-IAM-02 Disable account · SOP-IAM-03 Reset MFA · SOP-IAM-04 Run access review
Each SOP is written from the procedure actually run in the Entra ID hands-on (Steps 4, 5, 8b and 10). No tenant identifiers.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.expanduser("~/Downloads/HVMC_Crypto_Reports"))
from report_common import CSS  # noqa: E402

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
EXTRA = """
@page { size: Letter; margin: 0.48in 0.62in 0.5in 0.62in; }
body { font-size: 9.4pt; line-height: 1.33; }
h1 { font-size: 19pt; margin: 2px 0 2px; } .sub { font-size: 11.5pt; margin: 0 0 8px; }
h2 { font-size: 11.4pt; margin: 10px 0 4px; padding-bottom: 2px; border-bottom-width: 1.5px; }
ul, ol { margin: 3px 0 4px 0; padding-left: 18px; } li { margin: 1.5px 0; }
table.meta td { padding: 3px 7px; font-size: 8.8pt; }
.cols { display: grid; grid-template-columns: 1fr 1fr; gap: 0 22px; }
.never li::marker { content: "✗  "; color: #b3261e; }
.never li { color: #3a1d1b; }
code { font-size: 8.2pt; }
.foot { margin-top: 10px; font-size: 8pt; color: #666; border-top: 1px solid #c9d3e0; padding-top: 4px; }
"""


def ul(items, cls=""):
    return f'<ul class="{cls}">' + "".join(f"<li>{i}</li>" for i in items) + "</ul>"


def ol(items):
    return "<ol>" + "".join(f"<li>{i}</li>" for i in items) + "</ol>"


def sop(code, title, sub, meta, sections, example):
    rows = [("Project", "<b>AccessGuard Health</b> — Horizon Valley Medical Center (HVMC) Healthcare IAM"), ("SOP ID", code), ("Version / effective", "1.0 / 9 November 2026"), ("Owner", "IAM Administrator (Sabitha S Karanavar)"),
            ("Approved by", "IT Security (Security Supervisor)"), ("Review", "Every 12 months, or after any incident or tooling change")] + meta
    meta_html = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in rows)
    body = "".join(f"<h2>{h}</h2>{c}" for h, c in sections)
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>HVMC {code} {title}</title>
<style>{CSS}{EXTRA}</style></head><body>
<div class="runhead">AccessGuard Health &nbsp;|&nbsp; Horizon Valley Medical Center &nbsp;|&nbsp; Healthcare IAM Operations &nbsp;|&nbsp; Standard Operating Procedure</div>
<h1>{code}: {title}</h1><div class="sub">{sub}</div>
<table class="meta"><tbody>{meta_html}</tbody></table>
{body}
<div class="foot">Example run: {example} · System: Microsoft Entra ID (HVMC tenant, Free tier, security defaults on).
Every change runs as a dry run first; nothing is changed without -Apply / --apply.</div>
</body></html>"""


SOPS = {
 "SOP-IAM-01_Create_Account": sop(
  "SOP-IAM-01", "Create Account (Joiner)", "New employee or contractor gets an account with exactly the access their role needs",
  [("Performed by", "IAM Administrator (Entra role: User Administrator)"), ("Tool", "<code>Invoke-HvmcLifecycle.ps1</code> (HR feed) · RBAC v2 matrix")],
  [
   ("1. Trigger and inputs", ul([
     "HR feed row <code>Event = Join</code> with a ticket number (HVMC-JML-…) and the hiring manager's approval",
     "Required fields: Employee ID, given name, surname, department, job title, manager's employee ID, effective date",
     "Contractors: sponsor (an HVMC manager) and an end date are <b>mandatory</b>; no end date = no account"])),
   ("2. Before you start (checks)", ul([
     "Employee ID format <code>HVMC-&lt;dept code&gt;&lt;nn&gt;</code> (contractors <code>HVMC-C&lt;nnn&gt;</code>) and not already in use",
     "Department exists in the RBAC v2 matrix; manager's account exists and is enabled",
     "User name <code>firstname.lastname</code> is unique; the start date is today or earlier (future dates wait)"])),
   ("3. Procedure", ol([
     "Dry run: <code>./Invoke-HvmcLifecycle.ps1 -HrFeed &lt;feed&gt;.csv</code>; read the plan line by line",
     "Confirm the plan gives <b>only</b> the groups the RBAC matrix lists for that department and job title, nothing extra",
     "Apply: <code>./Invoke-HvmcLifecycle.ps1 -HrFeed &lt;feed&gt;.csv -Apply</code>",
     "Application access follows automatically from the groups (enterprise app sync); never assign apps by hand",
     "Initial password is random, never shown or stored, and must be changed at first sign-in",
     "Hand over through the help desk: password reset in person or by call-back, never by e-mail or chat",
     "User signs in, sets a new password and registers Microsoft Authenticator (security defaults require MFA)"])),
   ("4. Verify", ul([
     "Account enabled, attributes and manager correct, usage location set",
     "RBAC coverage check: the new user matches the matrix with 0 missing and 0 extra groups; app assignments present",
     "Re-running the same feed reports the event as “already done” (no duplicate account)"])),
   ("5. Evidence to keep", ul([
     "Plan and result JSON from the run (no passwords) · ticket updated and closed with the account name and date"])),
   ("6. Never", ul([
     "Copy another user's access (“make her the same as Jane”); access comes only from the matrix",
     "Send or read out a password by e-mail, chat or voicemail",
     "Give an admin role through this procedure; admin roles need a separate, approved change",
     "Create the account before HR has a record, or for a contractor without an end date"], "never")),
  ],
  "HVMC-JML-201 Olivia Bennett (20 Oct 2026, Nursing) and HVMC-JML-204 Ethan Morales (2 Nov 2026, from the HR feed)"),

 "SOP-IAM-02_Disable_Account": sop(
  "SOP-IAM-02", "Disable Account (Leaver)", "Remove all access when someone leaves, on time, without deleting the audit trail",
  [("Performed by", "IAM Administrator (Entra role: User Administrator); daily leaver check as the safety net"),
   ("Tool", "<code>Invoke-HvmcLifecycle.ps1</code> (HR feed) · <code>Invoke-HvmcLeaverCheck.ps1</code> (daily)")],
  [
   ("1. Trigger", ul([
     "<b>Planned leaver:</b> HR feed row <code>Event = Leave</code> with ticket, last day and end-of-shift time (UTC)",
     "<b>Urgent termination</b> (dismissal, security concern): request from HR or Security, confirmed by call-back to a known number; act immediately",
     "<b>Contractor end date reached:</b> found by the daily leaver check (warning 14 days before)"])),
   ("2. Procedure", ol([
     "Dry run: <code>./Invoke-HvmcLifecycle.ps1 -HrFeed &lt;feed&gt;.csv</code> (or <code>./Invoke-HvmcLeaverCheck.ps1</code>)",
     "Check the plan: block sign-in, revoke all sessions, remove every SG-* group, remove direct app assignments",
     "Apply at the leave time, not before (the person keeps working until the end of the shift): add <code>-Apply</code>",
     "Remove any <b>Azure (RBAC) role assignments</b> too; disabling the account does not remove them",
     "Record the leave date on the account; keep the account <b>disabled, not deleted</b> (audit and legal hold)",
     "Tell the manager the access is removed; ask for handover of shared files and devices"])),
   ("3. Verify", ul([
     "Account: sign-in blocked; sessions revoked; <b>0</b> groups; <b>0</b> application assignments; <b>0</b> Azure roles",
     "Run the leaver check again: “No leavers due” (nothing left to remove)",
     "RBAC coverage of the remaining staff unchanged; the leaver no longer appears in any group"])),
   ("4. Evidence to keep", ul([
     "Plan, results and before/after JSON from the run · ticket closed with the time access was removed"])),
   ("5. Never", ul([
     "Delete the account straight away; audit logs and investigations need it",
     "Disable only and stop there; a disabled account kept an Azure data role until the access review found it (lesson from Step 5)",
     "Use this procedure on admin or break-glass accounts (the scripts exclude them; they need a separate change)",
     "Remove access before the end of the last shift unless it is an urgent termination"], "never")),
  ],
  "HVMC-JML-203 Carlos Diaz (contractor, 20 Oct 2026) and HVMC-JML-206 Victor Mensah (2 Nov 2026, removed within 5 minutes of his shift ending)"),

 "SOP-IAM-03_Reset_MFA": sop(
  "SOP-IAM-03", "Reset MFA (Lost or Replaced Phone)", "Help the user back in with a new phone, without handing the account to an impostor",
  [("Performed by", "Help desk account <b>helpdesk.admin</b> (roles: Authentication Administrator + Reports Reader); never the Global Admin"),
   ("Tool", "<code>Invoke-HvmcMfaSupport.ps1 -Action Status | Reset | Verify</code>")],
  [
   ("1. Trigger", ul([
     "User reports a lost, stolen, broken or replaced phone and cannot approve Microsoft Authenticator sign-ins",
     "Open a ticket (IAM-…) with priority High: the lost phone could still approve sign-ins"])),
   ("2. Verify the caller first (most important step)", ul([
     "Call back on the phone number HR has on file, or confirm in person with photo ID, or confirmation from the manager",
     "Never trust the caller ID, an e-mail or a chat message alone; help-desk calls are a known way to take over accounts",
     "Admin accounts are <b>not</b> reset here (the script refuses); escalate to the IAM Administrator / break-glass process"])),
   ("3. Procedure", ol([
     "Status (read-only): <code>-Action Status</code>; note the current MFA methods and the time (ticket opened)",
     "Dry run: <code>-Action Reset</code>; check the plan: revoke sessions, remove the MFA methods only",
     "Apply: <code>-Action Reset -Apply -VerifiedBy \"&lt;how identity was checked&gt;\"</code>",
     "Sessions are revoked first (the lost phone is signed out), then the MFA methods are removed; password and reset e-mail are kept",
     "User signs in at <code>mysignins.microsoft.com/security-info</code> and registers the new phone <b>themselves</b>",
     "About 10 minutes later: <code>-Action Verify</code>; expect 6/6 checks passed"])),
   ("4. Verify and evidence", ul([
     "Entra audit log: “Admin deleted security info” by helpdesk.admin and “User registered security info” by the user",
     "Status / reset / verify evidence JSON (phone numbers masked) · ticket closed with opened/closed times and the identity-check method"])),
   ("5. Never", ul([
     "Reset MFA before the identity check, or record a check that did not happen",
     "Ask the user for a code, approve a prompt for them, or register a method on their behalf",
     "Use the Global Admin for routine resets; reset the password too unless it was also requested",
     "Skip the session revoke; the lost phone may still hold a signed-in session"], "never")),
  ],
  "Ticket IAM-0004, Dr. Sarah Chen (5 Nov 2026): opened 3:25 PM, closed 3:54 PM, Verify 6/6. Improvement to evaluate: Temporary Access Pass after the identity check"),

 "SOP-IAM-04_Run_Access_Review": sop(
  "SOP-IAM-04", "Run Access Review (Quarterly)", "Managers confirm who still needs which access; anything not justified is removed",
  [("Performed by", "IAM Administrator prepares and applies; managers and the Security Supervisor decide"),
   ("Tool", "<code>build_review_pack.py</code> (Excel review pack) · <code>apply_decisions.py</code>")],
  [
   ("1. Schedule and scope", ul([
     "Every quarter (campaign name HVMC-AR-YYYY-Qn); next: HVMC-AR-2027-Q1, January 2027",
     "In scope: every SG-* group membership, every direct application assignment, directory roles (Global Administrator), Azure role assignments, and disabled accounts that still hold any access"])),
   ("2. Reviewers", ul([
     "Each user's <b>manager</b> reviews their staff",
     "Department leads, test and admin accounts: IAM Administrator; privileged roles: Security Supervisor",
     "Nobody reviews their own access"])),
   ("3. Procedure", ol([
     "Take a read-only snapshot of the tenant and build the pack: <code>python3 build_review_pack.py</code>",
     "Each line shows the access, a rule-based flag (green / amber / red) and a recommendation",
     "Send the pack to reviewers with a due date (10 working days); unanswered lines are escalated to the Security Supervisor",
     "Reviewers record <b>Keep</b> or <b>Remove</b> on every line, with a short justification",
     "Dry run: <code>python3 apply_decisions.py</code>; check every Remove action",
     "Apply: <code>python3 apply_decisions.py --apply</code>; re-run the application sync and the RBAC coverage check",
     "Write findings for the next campaign (preparation notes)"])),
   ("4. Verify and evidence", ul([
     "Every removed access is gone (re-read from Entra ID / Azure); coverage check shows no extra access",
     "Keep: decided review pack (Excel), actions log (JSON), reviewer sign-off, findings and preparation notes"])),
   ("5. Never", ul([
     "Approve everything without reading it (“rubber-stamping”); a Keep needs a reason",
     "Let a reviewer decide on their own access",
     "Remove access without the dry run, or change decisions after sign-off without a new approval",
     "Skip disabled accounts: they are where forgotten access hides"], "never")),
  ],
  "HVMC-AR-2026-Q4 (20 Oct 2026): 94 lines, 93 Keep, 1 Remove (a disabled test account's Azure data role); legacy EHR app brought under group management"),
}

for name, page in SOPS.items():
    html_path = os.path.join(HERE, name + ".html")
    pdf_path = os.path.join(HERE, "HVMC_" + name + ".pdf")
    open(html_path, "w").write(page)
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={pdf_path}", "file://" + html_path],
                   capture_output=True, check=True)
    print("wrote", pdf_path)
