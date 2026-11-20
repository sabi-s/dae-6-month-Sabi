"""Builds HVMC_Cloud_Compliance_and_Governance_Controls.pdf (v2.0) from the live lab evidence.

Usage (from azure_governance_lab/):  python _report/build_report.py
Needs Google Chrome or Microsoft Edge for HTML -> PDF.
"""
import html
import json
import os
import subprocess
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
EV = LAB / "evidence"
OUT_PDF = LAB.parent / "HVMC_Cloud_Compliance_and_Governance_Controls.pdf"
OUT_HTML = LAB / "_report" / "report.html"

S = json.loads((EV / "07_compliance_summary.json").read_text(encoding="utf-8"))
G, H = S["hvmc-guardrails"], S["hvmc-hipaa-hitrust"]
T1, T2 = S["hvmc-tags-hvmc-cloudsecurity-rg"], S["hvmc-tags-hvmc-keyvault-rg"]
TAG_RES = T1["resources_evaluated"] + T2["resources_evaluated"]
TAG_OK = T1["resources_compliant"] + T2["resources_compliant"]
HIPAA_PCT = round(100 * H["resources_compliant"] / max(H["resources_evaluated"], 1))
CTRL_PCT = round(100 * (H["control_groups"] - H["control_groups_noncompliant"]) / max(H["control_groups"], 1))


def ev(name, start=None, end=None, max_lines=40):
    """Return lines of an evidence file (already masked) for an excerpt box."""
    lines = (EV / name).read_text(encoding="utf-8").splitlines()
    if start:
        i = next(k for k, l in enumerate(lines) if start in l)
        lines = lines[i:]
    if end:
        j = next((k for k, l in enumerate(lines) if end in l and k > 0), len(lines))
        lines = lines[:j]
    return html.escape("\n".join(l.rstrip() for l in lines[:max_lines]))


def term(text, caption):
    return (f'<div class="fig"><pre class="term">{text}</pre>'
            f'<div class="cap">{caption}</div></div>')


def row(*cells):
    return "<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>"


def table(head, rows, cls=""):
    return (f'<table class="{cls}"><thead><tr>' + "".join(f"<th>{h}</th>" for h in head) +
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>")


MET, PART, GAP = '<span class="met">MET</span>', '<span class="part">PARTIAL</span>', '<span class="gap">GAP</span>'

hipaa_nc_rows = []
for ref, res in sorted(H["noncompliant_by_policy"].items(), key=lambda x: -len(x[1])):
    hipaa_nc_rows.append(row(html.escape(H["policy_display_names"].get(ref) or ref), ", ".join(map(html.escape, res))))

style = (Path(__file__).resolve().parents[4] / "Semester_3/AccessGuard_Health_IAM_Project/02_Entra_ID_Hands_On_Operations/_tooling/report_style.html")
base = style.read_text(encoding="utf-8")
head_css = base[:base.index("</style>")] + """
pre.term { background:#1e2430; color:#e6edf3; font-family: Consolas, "Courier New", monospace; font-size:7.4pt; line-height:1.35;
  padding:8px 10px; border-radius:4px; white-space:pre-wrap; word-break:break-all; text-align:left; margin:0; }
.badge { display:inline-block; background:#1b7a3a; color:#fff; font-size:8pt; font-weight:bold; padding:2px 8px; border-radius:10px; }
.kpis { display:flex; gap:8px; margin:8px 0 12px; } .kpi { flex:1; border:1px solid #c9d3e0; border-radius:4px; padding:6px 8px; text-align:center; }
.kpi b { display:block; font-size:15pt; color:#1f3864; } .kpi span { font-size:8pt; color:#555; }
code { font-family: Consolas, monospace; font-size:8.6pt; background:#eef2f8; padding:0 3px; }
</style></head><body>"""

P = []
A = P.append

# ---------------- Cover ----------------
A('<div class="runhead">Semester 4 · Healthcare IAM Operations Home Lab · Cloud Security 1</div>')
A('<h1>Cloud Compliance &amp; Governance Controls</h1>')
A('<div class="sub">Framework Mapping &amp; Checklist, Gap Analysis &amp; Remediation, Policy Guardrails, '
  'Mandatory Tagging, and Automated Compliance Checking with Documented Enforcement Evidence</div>')
A('<div class="tag">Version 2.0 · 20 November 2026 · implemented live in Microsoft Azure</div>')
A(table(["Item", "Detail"], [
    row("Scenario organization", "Horizon Valley Medical Center (HVMC) – fictional hospital used throughout the capstone"),
    row("Capstone project", "AccessGuard Health – Azure / Entra ID IAM Operations"),
    row("Rubric item", "Cloud Compliance &amp; Governance Controls (Cloud Security 1)"),
    row("Framework mapped", "HIPAA Security Rule (45 CFR §164.308 / §164.312), crosswalked to NIST CSF 2.0 via NIST SP 800-66r2"),
    row("Environment", "HVMC Azure subscription (Pay-As-You-Go), region East US. Lab cost of this work: $0 "
                       "(Azure Policy, tags and resource locks are free)"),
    row("Evidence", "Scripts and masked CLI output in <code>azure_governance_lab/</code> next to this report"),
    row("Created by", "Sabitha S Karanavar"),
], "kv"))
# ---------------- Rubric cross-reference ----------------
A('<h2>Rubric Cross-Reference</h2>')
A(table(["Rubric requirement", "Where addressed"], [
    row("Map cloud configurations to one major compliance framework, creating a compliance checklist with gap analysis "
        "and remediation plans", "Section 1 – Framework Mapping &amp; Checklist; Section 2 – Gap Analysis &amp; Remediation Plan"),
    row("Configure AWS Organizations with Service Control Policies and mandatory resource tagging",
        "Section 3 – Governance Implementation (Azure equivalents: scope hierarchy, Azure Policy Deny guardrails, "
        "mandatory-tag initiative, resource locks; mapping in 3.1)"),
    row("Implement automated compliance checking using AWS Config Rules with documented evidence of policy enforcement",
        "Section 4 – Automated Compliance Checking (Azure Policy compliance with the built-in HITRUST/HIPAA initiative) "
        "and the enforcement evidence log in 4.3"),
]))

# ---------------- Section 1 ----------------
A('<h2 class="pb">1. Compliance Framework Mapping &amp; Checklist</h2>')
A('<h3>1.1 Framework selected</h3>')
A('<p>The HIPAA Security Rule is used, as in the rest of the HVMC compliance work, because HVMC stores electronic '
  'protected health information (ePHI). Each requirement is crosswalked to its NIST CSF 2.0 subcategory using '
  'NIST SP 800-66r2. Microsoft publishes a built-in Azure Policy initiative, <b>HITRUST/HIPAA</b> '
  f'({H["policies_evaluated"]} evaluated policies, {H["control_groups"]} control groups), which is assigned in Section 4 '
  'to check the subscription automatically.</p>')
A('<h3>1.2 Cloud compliance checklist (status on 20 Nov 2026)</h3>')
A(table(["Requirement", "HIPAA", "NIST CSF 2.0", "Azure control", "Before", "After"], [
    row("Unique user identification", "§164.312(a)(2)(i)", "PR.AA-01", "Named Entra ID accounts, two break-glass admins, no guest users (Entra Steps 1, 7, 11)", MET, MET),
    row("Access control / minimum necessary", "§164.312(a)(1)", "PR.AA-05", "Azure RBAC with custom role HVMC-Nurse-EHR-ReadOnly; Key Vault RBAC", MET, MET),
    row("Audit controls / logging", "§164.312(b)", "PR.PS-04, DE.CM-01", "Log Analytics + Microsoft Sentinel, 9 activity-log alerts; <b>new:</b> delete locks on the log workspace and log archive", PART, PART + " – retention 90 days"),
    row("Transmission security", "§164.312(e)(1)", "PR.DS-02", "<b>New:</b> Deny rules for HTTPS-only and minimum TLS 1.2 on storage", PART + " (not enforced)", MET),
    row("Preventive guardrails (risk management)", "§164.308(a)(1)(ii)(B)", "GV.PO-01, PR.PS-01", "<b>New:</b> HVMC-Guardrails initiative – approved region, no public storage", GAP, MET),
    row("Asset inventory &amp; accountability", "§164.310(d)(1), §164.308(a)(1)(ii)(A)", "ID.AM-01, ID.AM-02", "<b>New:</b> HVMC-Mandatory-Tags initiative – Owner, Environment, DataClassification", GAP + " (0 of 22 tagged)", MET + " (22 of 22)"),
    row("Information system activity review", "§164.308(a)(1)(ii)(D)", "DE.CM-01, ID.RA-01", "<b>New:</b> continuous Azure Policy evaluation with the HITRUST/HIPAA initiative", GAP, MET + f" – {H['policies_noncompliant']} findings open"),
]))
A('<p class="note">v1.0 cited PR.PT-01, a NIST CSF 1.1 identifier; CSF 2.0 moved logging to PR.PS-04 (corrected above).</p>')

# ---------------- Section 2 ----------------
A('<h2 class="pb">2. Gap Analysis &amp; Remediation Plan</h2>')
A('<h3>2.1 Measured before and after</h3>')
A(f'''<div class="kpis">
<div class="kpi"><b>0 → 22</b><span>resources with the mandatory tags (of 22)</span></div>
<div class="kpi"><b>1 → 5</b><span>policy assignments (Defender default + 4 HVMC)</span></div>
<div class="kpi"><b>0 → 2</b><span>delete locks on logging resources</span></div>
<div class="kpi"><b>4 / 4</b><span>policy-violating requests denied in testing</span></div></div>''')
A(table(["Gap", "Required state", "State before (baseline 18:59 UTC)", "Risk", "Status now"], [
    row("No preventive guardrails", "High-risk configurations blocked at the API before they exist", "Only the Defender for Cloud default initiative (audit only)", "HIGH", MET + " – HVMC-Guardrails, Section 3.2"),
    row("No mandatory tagging", "Every resource has an owner, environment and data classification", "22 of 22 resources missing the tags", "MEDIUM", MET + " – Section 3.3"),
    row("No automated compliance checking", "Continuous evaluation against HIPAA", "Manual, point-in-time checks", "HIGH", MET + " – Section 4"),
    row("Logging could be deleted", "Audit trail protected from deletion", "No locks", "HIGH", MET + " – Section 3.4"),
    row("Log retention too short", "Logs kept long enough for HIPAA documentation (6 years)", "Workspace retention 90 days", "HIGH", GAP + " – remediation 1"),
    row("Key Vault reachable from any network", "Firewall or private access", "Public network access enabled", "MEDIUM", GAP + " – flagged by Audit-KeyVault-Firewall"),
    row("Storage shared-key access allowed", "Entra ID authorization only", "Shared key allowed on both accounts", "MEDIUM", GAP + " – flagged by Audit-Storage-SharedKey"),
    row("MFA not enforced for admin changes", "MFA required for privileged actions", "Conditional Access CA001/CA002 in report-only", "HIGH", PART + " – Entra Step 06"),
]))
A('<h3>2.2 Remediation plan</h3>')
A(table(["#", "Recommendation", "Owner (acting role)", "Target"], [
    row("1", "Send the workspace's audit tables to a storage archive (or raise retention) so security logs are kept 6 years; review cost first", "IAM/Identity Administrator", "30 days"),
    row("2", "Enable the Key Vault firewall (allow the admin IP only) or move to private access", "IAM/Identity Administrator", "15 days"),
    row("3", "Disable shared-key access on the storage accounts after checking no tool depends on it", "IAM/Identity Administrator", "15 days"),
    row("4", "Move Conditional Access CA001/CA002 from report-only to On (Entra P2 trial active)", "IAM/Identity Administrator", "15 days"),
    row("5", f"Work through the {H['policies_noncompliant']} HITRUST/HIPAA findings in Section 4.2 and document accepted risks", "IAM/Identity Administrator", "30 days"),
    row("6", "Set expiry dates on the three Key Vault secrets (found in the 19 Nov security check; Audit-Secret-Expiry is a Key Vault data-plane rule and had not reported results when this report was written)", "IAM/Identity Administrator", "15 days"),
]))

# ---------------- Section 3 ----------------
A('<h2 class="pb">3. Governance Implementation</h2>')
A('<h3>3.1 AWS service named in the rubric → Azure control built</h3>')
A(table(["Rubric (AWS)", "Built in Azure", "How it was configured"], [
    row("AWS Organizations and OUs", "Scope hierarchy: subscription → resource groups", "Guardrails assigned at subscription scope (the “organization”); tag rules at the two HVMC workload resource groups (the “production OU”). Management groups were not used: they need tenant-root access, and HVMC has one subscription."),
    row("Service Control Policies", "Azure Policy initiative <b>HVMC-Guardrails</b>", "9 built-in policies; 5 with <b>Deny</b> effect block requests at the Azure Resource Manager API, like an SCP"),
    row("Mandatory resource tagging (tag policies)", "Initiative <b>HVMC-Mandatory-Tags</b>", "Modify: inherit 4 tags from the resource group; Deny: refuse resources without Owner, Environment or DataClassification"),
    row("SCP “Deny-Disable-Logging”", "Resource locks (CanNotDelete)", "On the Sentinel workspace and the security-log storage account"),
    row("AWS Config Rules", "Azure Policy compliance + built-in <b>HITRUST/HIPAA</b> initiative", "Audit-only assignment at subscription; evaluated automatically about every 24 h and on every change"),
]))
A('<h3>3.2 HVMC-Guardrails (subscription scope)</h3>')
A(table(["Rule (reference ID)", "Built-in policy", "Effect", "Purpose"], [
    row("Restrict-Regions", "Allowed locations = eastus", "Deny", "Data residency – resources only in the approved region"),
    row("Restrict-Regions-ResourceGroups", "Allowed locations for resource groups = eastus", "Deny", "Same rule for resource groups"),
    row("Deny-Public-Storage", "Storage account public access should be disallowed", "Deny", "No anonymous access to ePHI blobs"),
    row("Deny-Insecure-Transfer", "Secure transfer to storage accounts should be enabled", "Deny", "HTTPS only (§164.312(e)(1))"),
    row("Deny-Old-TLS", "Storage accounts should have the specified minimum TLS version (TLS1_2)", "Deny", "No TLS 1.0/1.1"),
    row("Audit-Storage-SharedKey", "Storage accounts should prevent shared key access", "Audit", "Flags key-based access (not denied yet – existing tools may use keys)"),
    row("Audit-KeyVault-Firewall", "Azure Key Vault should have firewall enabled or public network access disabled", "Audit", "Flags open Key Vault network access"),
    row("Audit-KeyVault-Logs", "Resource logs in Key Vault should be enabled", "AuditIfNotExists", "Checks Key Vault audit logging"),
    row("Audit-Secret-Expiry", "Key Vault secrets should have an expiration date", "Audit", "Flags secrets that never expire"),
]))
A('<p>Two rules start in <b>Audit</b> instead of Deny on purpose: denying them now would block updates to existing '
  'resources that still use shared keys or open network access. They move to Deny after remediation items 2 and 3.</p>')
A('<h3>3.3 Mandatory resource tagging</h3>')
A(table(["Tag key", "Required?", "HVMC-CloudSecurity-RG", "HVMC-KeyVault-RG", "Purpose"], [
    row("Owner", "Yes (Deny)", "IAM-Admin", "IAM-Admin", "Accountable person or role – ownership is set at creation, not found later in an audit"),
    row("Environment", "Yes (Deny)", "lab", "lab", "Scopes policies and separates lab from production"),
    row("DataClassification", "Yes (Deny)", "ephi-simulated", "secrets", "Marks resources that hold ePHI or secrets for the strictest controls"),
    row("CostCenter", "Inherited", "hvmc-capstone", "hvmc-capstone", "Budget tracking (ties to the HVMC monthly budgets)"),
]))
A('<p>Enforcement has two layers. The <b>Modify</b> rules copy the resource group’s tags onto any new or updated '
  'resource, so engineers do not have to remember them; the <b>Deny</b> rules are the backstop if a tag is still missing. '
  'Proof that the Modify layer works is in Section 4.3 (test account tagged automatically).</p>')
A(term(ev("02_assign_policies.txt", "== Policy assignments after Step 2", None, 10) + "\n\n" +
       html.escape("Resource-group-scope assignments (az policy assignment list --disable-scope-strict-match):\n"
                   "HVMC-Mandatory-Tags (HVMC-CloudSecurity-RG)\nHVMC-Mandatory-Tags (HVMC-KeyVault-RG)"),
       "Figure 1 – Policy assignments after Step 2 (evidence/02_assign_policies.txt)"))
A('<h3>3.4 Protecting the audit trail</h3>')
A(term(ev("03_protect_logging.txt", "== Locks after Step 3"), "Figure 2 – CanNotDelete locks (evidence/03_protect_logging.txt)"))
A('<p>With these locks, nobody – including an Owner – can delete the Sentinel workspace or the log archive without '
  'first removing the lock, and lock removal is itself recorded in the activity log. Logs can still be written and '
  'queried. Analytics rules should be disabled rather than deleted while the lock is in place.</p>')

# ---------------- Section 4 ----------------
A('<h2 class="pb">4. Automated Compliance Checking &amp; Documented Evidence</h2>')
A('<h3>4.1 Compliance results (after scan)</h3>')
A(table(["Assignment", "Scope", "Resources evaluated", "Compliant", "Non-compliant", "Non-compliant rules"], [
    row("HVMC-Guardrails", "Subscription", G["resources_evaluated"], G["resources_compliant"], G["resources_noncompliant"], G["policies_noncompliant"]),
    row("HVMC-Mandatory-Tags", "2 HVMC resource groups", TAG_RES, TAG_OK, TAG_RES - TAG_OK, T1["policies_noncompliant"] + T2["policies_noncompliant"]),
    row("HITRUST/HIPAA (audit only)", "Subscription", H["resources_evaluated"], H["resources_compliant"], H["resources_noncompliant"], H["policies_noncompliant"]),
]))
A(f'<p>HITRUST/HIPAA: <b>{H["control_groups"] - H["control_groups_noncompliant"]} of {H["control_groups"]}</b> control groups '
  f'({CTRL_PCT}%) have no non-compliant resource; <b>{H["control_groups_noncompliant"]}</b> control groups are affected by '
  f'the {H["policies_noncompliant"]} findings below. Most of the initiative’s policies target services HVMC does not run '
  '(VMs, SQL, Kubernetes) and therefore have no resources to evaluate.</p>')
A(term(ev("06_compliance_results.txt", "== Resources missing mandatory tags", "== Policy deny events"), "Figure 6 – Tags and compliance after the backfill and scan (evidence/06_compliance_results.txt)"))
A('<h3>4.2 HITRUST/HIPAA findings</h3>')
A(table(["Policy (Microsoft built-in)", "Non-compliant resources"], hipaa_nc_rows))
A('<p class="note">The three Owner-related findings (guest, blocked and single owner) all point to the one Owner of the '
  'lab subscription: the personal Microsoft account it was created with, which Entra ID lists as an external '
  '(#EXT#) user. In production they would be fixed by assigning Owner to two named accounts from the organization’s own '
  'directory and using the break-glass accounts for emergencies. The custom-role finding is the reviewed role '
  'HVMC-Nurse-EHR-ReadOnly. The activity-log-alert finding names specific operations (for example, policy assignment '
  'changes) that HVMC’s 9 existing alerts do not cover yet.</p>')

A('<h3>4.3 Documented evidence of policy enforcement</h3>')
A(table(["#", "Control / rule", "Mechanism", "Test (20 Nov 2026, UTC)", "Result"], [
    row("1", "Restrict-Regions-ResourceGroups", "Preventive – API deny", "Create resource group HVMC-PolicyTest-RG in westus (19:05 and 19:06)", '<span class="gap">DENIED</span> RequestDisallowedByPolicy'),
    row("2", "Restrict-Regions", "Preventive – API deny", "Create a storage account in westus (19:05 and 19:06)", '<span class="gap">DENIED</span>'),
    row("3", "Deny-Public-Storage", "Preventive – API deny", "Create a storage account with public blob access (19:05 and 19:06)", '<span class="gap">DENIED</span>'),
    row("4", "Deny-Insecure-Transfer", "Preventive – API deny", "Create a storage account with HTTP allowed (19:05 and 19:06)", '<span class="gap">DENIED</span>'),
    row("5", "Inherit-Owner/Environment/DataClassification/CostCenter", "Preventive – Modify", "Compliant test storage account created without tags (19:05)", '<span class="met">TAGGED AUTOMATICALLY</span> – 4 tags added; account then deleted'),
    row("6", "Require-&lt;tag&gt; (Deny) vs. remediation", "Preventive – API deny", "Remediation tasks adding one tag at a time to existing resources (19:24–19:25)", '<span class="gap">DENIED</span> 79 requests; 7 of 8 tasks failed – see 4.4'),
    row("7", "Backfill with full tag set", "Corrective", "One request per resource with all 4 tags (19:26–19:29)", '<span class="met">22 of 22 COMPLIANT</span>'),
    row("8", "Audit-KeyVault-Firewall, Audit-Storage-SharedKey", "Detective – audit", "Compliance scan", '<span class="part">FLAGGED</span> – real gaps, remediation 2–3'),
]))
A('<p>The activity log recorded <b>87 policy deny events</b> on the lab day: 8 from tests 1–4 (each run twice) and 79 from '
  'the remediation conflict (evidence/06_compliance_results.txt). Every test was run with the Azure CLI as the subscription Owner, '
  'which shows the guardrails also apply to the highest-privileged role.</p>')
A(term(ev("04_enforcement_tests.txt", "---- TEST 1", "---- TEST 3"), "Figure 3 – Tests 1 and 2 refused by Azure Policy (evidence/04_enforcement_tests.txt)"))
A(term(ev("04b_test5_followup.txt"), "Figure 4 – Modify rule tagged a new resource automatically (evidence/04b_test5_followup.txt)"))
A(term(ev("05_remediation_failures.txt", "== Sample failure"), "Figure 5 – Deny rule refusing a single-tag remediation (evidence/05_remediation_failures.txt)"))

A('<h3>4.4 Lessons learned</h3>')
A('<ul>'
  '<li><b>Modify and Deny conflict during remediation.</b> Azure remediation tasks apply one Modify rule per request. '
  'With three Require-tag Deny rules, a request that adds only Owner is refused because Environment and '
  'DataClassification are still missing. Fix: a one-time backfill that writes all tags in one request '
  '(<code>05b_backfill_tags.sh</code>). New resources are not affected, because all Modify rules run on the same create request.</li>'
  '<li><b>Deny rules see only what the request sends.</b> A storage request that omits <code>minimumTlsVersion</code> or '
  '<code>allowBlobPublicAccess</code> is denied even though Azure’s defaults are secure. Templates must state secure '
  'settings explicitly.</li>'
  '<li><b>A planned TLS 1.0 test could not fail.</b> Azure retired TLS 1.0/1.1 on 3 Feb 2026, so the CLI upgraded the '
  'request to TLS 1.2 and it was correctly allowed. The test was dropped and the account deleted.</li>'
  '<li><b>Tag key case.</b> The Key Vault had <code>owner</code> in lowercase. Azure Policy treats tag names as '
  'case-insensitive, but CLI queries do not, so the key was normalised to <code>Owner</code>.</li>'
  '</ul>')

# ---------------- Section 5 ----------------
A('<h2 class="pb">5. How to Verify in the Azure Portal</h2>')
A(table(["What", "Portal path"], [
    row("Policy assignments", "Azure portal &gt; Policy &gt; Authoring &gt; Assignments (scope: Azure subscription 1)"),
    row("Initiative definitions", "Policy &gt; Authoring &gt; Definitions &gt; Category = HVMC-Governance"),
    row("Compliance dashboard", "Policy &gt; Compliance &gt; select HITRUST/HIPAA (audit only) or HVMC-Guardrails"),
    row("Denied requests", "Monitor &gt; Activity log &gt; filter Operation = ‘Deny’ (Microsoft.Authorization/policies/deny/action)"),
    row("Remediation tasks", "Policy &gt; Remediation &gt; Remediation tasks"),
    row("Tags", "Resource groups &gt; HVMC-CloudSecurity-RG &gt; Tags, or All resources &gt; add column Tags"),
    row("Locks", "Resource groups &gt; HVMC-CloudSecurity-RG &gt; Settings &gt; Locks"),
]))
A('<h3>5.1 Evidence files</h3>')
A(table(["File", "Content"], [
    row("00_baseline.txt", "State before any change: 1 assignment, 0 locks, 22 of 22 resources untagged"),
    row("01 – 03", "Resource-group tags, policy initiatives and assignments, locks"),
    row("04_enforcement_tests.txt, 04b_test5_followup.txt", "Deny tests and the automatic-tagging proof"),
    row("05_*, 05b_backfill_tags.txt", "Remediation results, failure cause and the backfill"),
    row("06_compliance_results.txt, 07_compliance_summary.json", "Compliance results after the scan"),
    row("policy/*.json", "The two HVMC initiative definitions"),
]))
A('<p class="foot">Sources: NIST SP 800-66r2, Implementing the HIPAA Security Rule: A Cybersecurity Resource Guide; '
  'NIST Cybersecurity Framework 2.0; HHS, 45 CFR §164.308/.310/.312; Microsoft Learn – Azure Policy built-in initiative '
  'HITRUST/HIPAA, Azure Policy effects (Modify, Deny), Azure resource locks. Prepared as the Cloud Compliance &amp; '
  'Governance Controls deliverable for the Semester 4 Healthcare IAM Operations Home Lab capstone.</p>')

OUT_HTML.write_text(head_css + "\n".join(P) + "</body></html>", encoding="utf-8")

browser = next(p for p in [r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                           r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"] if os.path.exists(p))
subprocess.run([browser, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                f"--print-to-pdf={OUT_PDF}", OUT_HTML.as_uri()], check=True, capture_output=True)
print("Wrote", OUT_PDF)
