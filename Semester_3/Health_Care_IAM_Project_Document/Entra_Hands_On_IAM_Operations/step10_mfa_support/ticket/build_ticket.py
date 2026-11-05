"""Build Ticket_IAM-0004_MFA_Support.pdf from IAM-0004.json and the Step 10 evidence (no IDs, no phone numbers).

Before the activity is done it renders a template with [placeholders]; after Status/Reset/Verify have run it fills
the before/after, actions and verification from evidence/*.json. Screenshots go in ticket/screenshots/.
"""
import glob
import html
import json
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
EVID = os.path.join(HERE, "..", "evidence")
SHOTS = os.path.join(HERE, "screenshots")
OUT_HTML = os.path.join(HERE, "Ticket_IAM-0004_MFA_Support.html")
OUT_PDF = os.path.join(HERE, "Ticket_IAM-0004_MFA_Support.pdf")
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
T = json.load(open(os.path.join(HERE, "IAM-0004.json")))
e = html.escape


def latest(kind):
    files = sorted(glob.glob(os.path.join(EVID, f"*_{kind}.json")))
    return json.load(open(files[-1], encoding="utf-8-sig")) if files else None


def ph(text):
    return f'<span class="ph">[{e(text)}]</span>'


status, reset, verify = latest("mfa_status"), latest("mfa_reset"), latest("mfa_verify")


def methods(state):
    if not state:
        return None
    m = [x for x in state["methods"] if x["type"] not in ("Password", "Email (password reset only)")]
    return "; ".join(f'{x["type"]} ({x["detail"]})' if x["detail"] else x["type"] for x in m) or "None"


def hhmm(iso):
    return iso[11:16] + " UTC" if iso else ""


before = (reset or {}).get("before") or (status or {}).get("state")
after_reset = (reset or {}).get("after")
final = (verify or {}).get("state")
rows = [
    ["System", "Microsoft Entra ID (HVMC tenant), security defaults on", "Same"],
    ["Username", "sarah.chen", "sarah.chen"],
    ["Account state", "Enabled" if not before or before["accountEnabled"] else "Disabled",
     "Enabled" if not final or final["accountEnabled"] else "Disabled"],
    ["MFA methods", (methods(before) + " (old phone)") if methods(before) else ph("from the Status run"),
     ("Removed at reset; then " + methods(final) + " newly registered by the user (new phone)") if methods(final) else ph("from the Verify run")],
    ["Sign-in sessions", "Active, including on the lost phone",
     f'Revoked at {hhmm(reset["startedAt"])}' if reset else ph("from the Reset run")],
    ["Password", "Set", T.get("password_after", "Unchanged (not part of an MFA reset)")],
    ["Group and app access", "SG-Doctors-EHR-RW and its apps", "Unchanged"],
]

if reset:
    actions = [f'{e(r["time"])} UTC — {e(r["step"])}: {e(r["result"])}' for r in reset["results"]]
else:
    actions = [ph("filled from the Reset run: time and result of each step")]
actions = [
    "Ticket opened; recorded the before state of the account and its MFA methods (read-only Status run).",
    f'Verified the caller\'s identity before any change: {e(reset["identityVerifiedBy"]) if reset else ph("how identity was verified")}.',
    "Ran the reset as a dry run first and checked the plan.",
] + actions + [
    "Asked Dr. Chen to sign in and register her new phone on her Security info page; she did it herself.",
    "Ran the Verify check and reviewed the audit log, then closed the ticket.",
]

if verify:
    checks = [[k, "Yes", "Yes" if v else "No"] for k, v in verify["checks"].items()]
else:
    checks = [[k, "Yes", ph("result")] for k in ("identity verified before the reset", "old MFA methods removed at reset",
              "new MFA method registered after the reset", "audit: admin deleted security info",
              "audit: user registered security info", "account still enabled")]

audit = (final or {}).get("audit") or []
audit_rows = [[a["Time"][:16].replace("T", " ") if isinstance(a["Time"], str) else str(a["Time"]), e(a["Activity"]), e(a["Result"]), e(a["By"])] for a in audit]


def table(head, body, widths=None):
    cols = "".join(f'<col style="width:{w}">' for w in widths) if widths else ""
    th = "".join(f"<th>{h}</th>" for h in head)
    tr = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in body)
    return f'<table class="grid"><colgroup>{cols}</colgroup><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table>'


def figure(i, f, cap):
    path = os.path.join(SHOTS, f)
    img = f'<img src="screenshots/{f}">' if os.path.exists(path) else f'<div class="noimg">{ph("screenshot " + f)}</div>'
    return f'<figure>{img}<figcaption>Figure {i}: {e(cap)}</figcaption></figure>'


meta = [("Ticket ID", T["ticket"]), ("Related", T["related"]), ("Request type", T["request_type"]), ("Priority", T["priority"]),
        ("Status", T["status"] if verify else "Open (template)"), ("Date", T["date"]),
        ("Opened / closed", (T["opened"] or ph("time opened")) + " / " + (T["closed"] or ph("time closed"))),
        ("Requester", T["requester"]), ("Approver", T["approver"]), ("Handled by", T["handled_by"]), ("Employee", T["employee"])]

body = f"""
<div class="run">AccessGuard Health | Horizon Valley Medical Center | Healthcare IAM Operations Simulation</div>
<h1>IAM Ticket {T["ticket"]}: {e(T["title"])}</h1>
<div class="sub">AccessGuard Health – Healthcare IAM Operations Simulation</div>
<table class="meta">{"".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in meta)}</table>

<h2>Request</h2><p>{e(T["request"])}</p>

<h2>Identity Verification</h2>
<p>{e(T["verification_note"])}</p>
<table class="meta"><tr><th>Method</th><td>{e(reset["identityVerifiedBy"]) if reset else ph("e.g. call-back to the phone number HR has on file")}</td></tr>
<tr><th>Result</th><td>{"Identity confirmed before the reset" if reset else ph("confirmed / not confirmed")}</td></tr></table>

<h2>Systems and Account Changes</h2>
{table(["Item", "Before", "After"], rows, ["22%", "39%", "39%"])}

<h2>Actions Taken</h2>
<ul>{"".join(f"<li>{a}</li>" for a in actions)}</ul>

<h2>Verification</h2>
{table(["Check", "Expected", "Result"], checks, ["58%", "18%", "24%"])}
{("<h3>Audit trail (Entra ID)</h3>" + table(["Time (UTC)", "Activity", "Result", "By"], audit_rows, ["20%", "44%", "12%", "24%"])) if audit_rows else ""}

<h2>Resolution Notes</h2>
<ul>{"".join(f"<li>{e(x)}</li>" for x in T["resolution_notes"])}</ul>
<h3>Lessons learned</h3>
<ul>{"".join(f"<li>{e(x)}</li>" for x in T["lessons"])}</ul>

<h2>Evidence</h2>
<p>Evidence files are kept locally in step10_mfa_support/evidence (not on GitHub). Phone numbers and directory IDs are not shown.</p>
{"".join(figure(i + 1, f, c) for i, (f, c) in enumerate(T["figures"]))}
"""

CSS = """
@page { size: Letter; margin: 0.8in 0.9in 0.8in;
  @bottom-center { content: "Page " counter(page) " of " counter(pages); font: 9pt Calibri, Carlito, "Helvetica Neue", Arial; color: #555; } }
body { font-family: Calibri, Carlito, "Helvetica Neue", Arial, sans-serif; font-size: 11pt; color: #111; line-height: 1.35; }
.run { text-align: right; font-size: 8.5pt; font-style: italic; color: #555; border-bottom: 1px solid #bbb; padding-bottom: 3px; margin-bottom: 22px; }
h1 { text-align: center; font-size: 20pt; margin: 0 0 4px; }
.sub { text-align: center; color: #2f5597; font-weight: 700; font-size: 13pt; margin-bottom: 10px; }
h2 { color: #2f5597; font-size: 14pt; margin: 18px 0 6px; }
h3 { color: #2f5597; font-size: 11.5pt; margin: 12px 0 4px; }
table { border-collapse: collapse; width: 100%; margin: 6px 0 10px; font-size: 9.8pt; }
td, th { border: 1px solid #b7b7b7; padding: 4px 7px; vertical-align: top; text-align: left; }
table.meta th { background: #dce6f2; width: 28%; font-weight: 700; }
table.grid th { background: #dce6f2; }
ul { margin: 4px 0 8px 18px; padding: 0; } li { margin: 2px 0; }
figure { margin: 10px 0; text-align: center; break-inside: avoid; }
figure img { max-width: 100%; border: 1px solid #ccc; }
figcaption { font-size: 9pt; color: #444; margin-top: 3px; }
.ph { color: #b9770e; font-style: italic; }
.noimg { border: 1px dashed #b9770e; padding: 18px; }
"""
open(OUT_HTML, "w").write(f'<!doctype html><html><head><meta charset="utf-8"><title>Ticket IAM-0004</title><style>{CSS}</style></head><body>{body}</body></html>')
subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", "--allow-file-access-from-files",
                f"--print-to-pdf={OUT_PDF}", "file://" + OUT_HTML], capture_output=True, check=True)
print("wrote", OUT_PDF, "(template)" if not verify else "(filled)")
