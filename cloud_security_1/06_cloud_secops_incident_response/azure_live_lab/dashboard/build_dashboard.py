"""
Build the HVMC Security Operations dashboard (single self-contained HTML file) from metrics.json + triage.json.

Horizon Valley Medical Center - Cloud Security Operations & Incident Response
Author: Sabitha S Karanavar

    python3 collect_metrics.py && python3 build_dashboard.py     # -> HVMC_SecOps_Dashboard.html
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def main():
    m = json.load(open(os.path.join(HERE, "metrics.json")))
    triage = json.load(open(os.path.join(HERE, "triage.json")))
    for a in m["alerts_fired"]:                      # attach the analyst's disposition to each fired alert
        t = next((t for t in triage if t["rule"] == a["rule"] and t["from"] <= a["start"][:19] + "Z" <= t["to"]), None)
        a["disposition"] = t["disposition"] if t else "Untriaged"
        a["note"] = t["note"] if t else ""
    for k in ("activity_hourly", "security_changes", "callers", "ingestion", "flows", "epHI_access"):
        for r in m.get(k, []):
            for f in ("Events", "Count", "Operations", "Failed", "MB", "Flows", "Requests"):
                if f in r:
                    r[f] = num(r[f])
    html = TEMPLATE.replace("/*DATA*/null", json.dumps(m)).replace("/*TRIAGE*/null", json.dumps(triage))
    out = os.path.join(HERE, "HVMC_SecOps_Dashboard.html")
    open(out, "w").write(html)
    print(out)


TEMPLATE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>HVMC SecOps Dashboard</title>
<style>
:root{color-scheme:light;
 --page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--grid:#e1e0d9;--axis:#c3c2b7;--ring:rgba(11,11,11,.10);
 --s1:#2a78d6;--s2:#eb6834;--s3:#1baa8f;--s4:#8a5cd6;--crit:#d03b3b;--serious:#ec835a;--warn:#fab219;--good:#0ca30c;--wash:rgba(42,120,214,.08);--navy:#1f3864}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme="light"])){color-scheme:dark;
 --page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);
 --s1:#3987e5;--s2:#d95926;--s3:#23b89b;--s4:#9a72e0;--wash:rgba(57,135,229,.14);--navy:#9ec5f4}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;
 --ring:rgba(255,255,255,.10);--s1:#3987e5;--s2:#d95926;--s3:#23b89b;--s4:#9a72e0;--wash:rgba(57,135,229,.14);--navy:#9ec5f4}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1280px;margin:0 auto;padding:16px}
header{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:baseline;justify-content:space-between}
h1{font-size:20px;margin:0;color:var(--navy)} h2{font-size:15px;margin:0 0 10px;color:var(--navy)}
.sub{color:var(--ink2);font-size:12.5px}
.card{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:14px;min-width:0}
.grid{display:grid;gap:12px;margin-top:12px}
.tiles{grid-template-columns:repeat(auto-fit,minmax(170px,1fr))}
.tile .v{font-size:28px;font-weight:650;font-variant-numeric:tabular-nums}
.tile .l{color:var(--ink2);font-size:12.5px} .tile .d{font-size:12px;color:var(--muted);margin-top:2px}
.two{grid-template-columns:minmax(0,1fr) minmax(0,1fr)} @media (max-width:900px){.two{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;color:var(--ink2);font-weight:600;border-bottom:1px solid var(--axis);padding:6px 6px}
td{border-bottom:1px solid var(--grid);padding:6px;vertical-align:top}
.scroll{overflow-x:auto}
.st{display:inline-flex;align-items:center;gap:5px;font-weight:600;font-size:12px;white-space:nowrap}
.st i{font-style:normal;display:inline-grid;place-items:center;width:16px;height:16px;border-radius:50%;color:#fff;font-size:10px}
.ok i{background:var(--good)} .bad i{background:var(--crit)} .warn i{background:var(--warn);color:#0b0b0b} .info i{background:var(--s1)}
.muted{color:var(--muted)} .small{font-size:12px}
.legend{display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--ink2);margin:4px 0 6px}
.legend span::before{content:"";display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;background:var(--c);vertical-align:-1px}
svg text{fill:var(--ink2);font-size:11px}
#tip{position:fixed;pointer-events:none;background:var(--surface);color:var(--ink);border:1px solid var(--ring);border-radius:8px;padding:6px 9px;
 font-size:12px;box-shadow:0 4px 14px rgba(0,0,0,.18);display:none;max-width:320px;z-index:5}
.bar{display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--grid)} .bar b{display:block;height:100%}
button.theme{background:var(--surface);color:var(--ink2);border:1px solid var(--ring);border-radius:8px;padding:4px 10px;font:inherit;font-size:12px;cursor:pointer}
footer{color:var(--muted);font-size:12px;margin:16px 0 4px}
</style></head><body><div class="wrap">
<header><div><h1>HVMC Security Operations Dashboard</h1>
<div class="sub" id="meta"></div></div>
<button class="theme" id="tbtn" type="button">Toggle dark mode</button></header>

<div class="grid tiles" id="tiles"></div>

<div class="grid two">
 <div class="card"><h2>Logging coverage</h2><div class="scroll"><table id="cov"></table></div></div>
 <div class="card"><h2>Security alerts fired (last 7 days)</h2><div class="legend" id="alegend"></div><div id="achart"></div>
  <div class="scroll"><table id="alerts"></table></div></div>
</div>

<div class="grid two">
 <div class="card"><h2>Control-plane activity per hour (last 48 h)</h2><div class="legend" id="hlegend"></div><div id="hchart"></div>
  <div class="small muted">Source: AzureActivity in HVMC-SecOps-LAW.</div></div>
 <div class="card"><h2>Security-relevant changes (last 7 days)</h2><div id="chg"></div>
  <h2 style="margin-top:14px">Who is making changes</h2><div class="scroll"><table id="callers"></table></div></div>
</div>

<div class="grid two">
 <div class="card"><h2>Incidents (Microsoft Sentinel)</h2><div id="inc"></div></div>
 <div class="card"><h2>Detection rules</h2><div class="scroll"><table id="rules"></table></div></div>
</div>

<div class="grid two">
 <div class="card"><h2>Security posture (Defender for Cloud)</h2><div id="posture"></div></div>
 <div class="card"><h2>Cost guard (trial credit used)</h2><div id="cost"></div></div>
</div>
<footer>Read-only data collected by collect_metrics.py · triage dispositions from triage.json · Horizon Valley Medical Center · Sabitha S Karanavar</footer>
</div><div id="tip"></div>
<script>
const M = /*DATA*/null, TRI = /*TRIAGE*/null;
const $ = s => document.querySelector(s), esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const tip = $("#tip");
function showTip(e, html){ tip.innerHTML = html; tip.style.display = "block";
  const x = Math.min(e.clientX + 14, innerWidth - tip.offsetWidth - 8), y = Math.min(e.clientY + 14, innerHeight - tip.offsetHeight - 8);
  tip.style.left = x + "px"; tip.style.top = y + "px"; }
document.addEventListener("mouseout", e => { if (e.target.dataset && e.target.dataset.tip) tip.style.display = "none"; });
document.addEventListener("mousemove", e => { const t = e.target.dataset && e.target.dataset.tip; if (t) showTip(e, t); });
$("#tbtn").onclick = () => { const r = document.documentElement, dark = r.dataset.theme ? r.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  r.dataset.theme = dark ? "light" : "dark"; try { localStorage.setItem("hvmc-theme", r.dataset.theme); } catch (e) {} };
try { const t = localStorage.getItem("hvmc-theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) {}
const st = (cls, icon, label) => `<span class="st ${cls}"><i aria-hidden="true">${icon}</i>${esc(label)}</span>`;
const fmtT = s => new Date(s).toLocaleString([], {month:"short", day:"numeric", hour:"2-digit", minute:"2-digit"});

// ---- header + tiles
const hrsLeft = Math.max(0, (new Date(M.trial_end) - new Date(M.generated)) / 36e5);
$("#meta").textContent = `Azure subscription ${M.subscription} · workspace ${M.workspace} · data collected ${fmtT(M.generated)} · free trial ends ${fmtT(M.trial_end)} (${hrsLeft.toFixed(0)} h left)`;
const covOk = M.coverage.filter(c => c.ok).length, inc = M.incidents || [];
const openInc = inc.filter(i => i.Status !== "Closed").length;
const untriaged = M.alerts_fired.filter(a => a.disposition === "Untriaged").length;
const closed = inc.filter(i => i.ClosedTime);
const mttr = closed.length ? (closed.reduce((s, i) => s + Number(i.MinutesToClose || 0), 0) / closed.length).toFixed(0) + " min" : "—";
const tiles = [
  [`${covOk}/${M.coverage.length}`, "Log sources connected", "1 known gap: Entra ID logs (licence)"],
  [`${M.alert_rules.filter(r => r.enabled).length + M.analytics_rules.filter(r => r.enabled).length}`, "Detection rules enabled", `${M.alert_rules.length} alert rules · ${M.analytics_rules.length} Sentinel rules`],
  [`${M.alerts_fired.length}`, "Alerts fired · 7 days", untriaged ? `${untriaged} untriaged` : "all triaged"],
  [`${openInc}`, "Open incidents", `${inc.length} total · mean time to close ${mttr}`],
  [M.secure_score ? `${M.secure_score.pct}%` : "—", "Defender secure score", M.secure_score ? `${M.secure_score.current} of ${M.secure_score.max} points` : ""],
  M.cost ? [`$${M.cost.total.toFixed(2)}`, "Trial credit used (of $200)", M.cost.stale ? `as of ${fmtT(M.cost.as_of)} (cost API throttled) · SecOps $0.00` : "SecOps tooling: $0.00"] : ["—", "Trial credit used (of $200)", "cost data unavailable this run"],
];
$("#tiles").innerHTML = tiles.map(t => `<div class="card tile"><div class="v">${esc(t[0])}</div><div class="l">${esc(t[1])}</div><div class="d">${esc(t[2])}</div></div>`).join("");

// ---- coverage
$("#cov").innerHTML = "<tr><th>Source</th><th>Status</th><th>Detail</th></tr>" + M.coverage.map(c =>
  `<tr><td>${esc(c.source)}</td><td>${c.ok ? st("ok", "✓", "Connected") : c.gap ? st("warn", "!", "Known gap") : st("bad", "✕", "Missing")}</td><td class="muted">${esc(c.detail)}</td></tr>`).join("");

// ---- alerts chart: one bar per hour, stacked by rule (fixed colour per rule, never by rank)
const RULE_COLORS = {}, PALETTE = ["--s1", "--s2", "--s3", "--s4"];
[...new Set(M.alerts_fired.map(a => a.rule))].sort().forEach((r, i) => RULE_COLORS[r] = PALETTE[i % PALETTE.length]);
function stackedBars(el, rows, keyOf, seriesOf, colorOf, opts){
  const W = 560, H = 170, L = 34, B = 26, T = 8;
  const keys = [...new Set(rows.map(keyOf))].sort(), series = [...new Set(rows.map(seriesOf))].sort();
  const val = (k, s) => rows.filter(r => keyOf(r) === k && seriesOf(r) === s).reduce((a, r) => a + (opts.value ? opts.value(r) : 1), 0);
  const tot = keys.map(k => series.reduce((a, s) => a + val(k, s), 0)), max = Math.max(1, ...tot);
  const nice = Math.ceil(max / 5) * 5 || 5, bw = Math.min(46, (W - L - 10) / Math.max(keys.length, 1) - 8);
  let svg = `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="${esc(opts.label)}">`;
  for (let g = 0; g <= 5; g++){ const y = T + (H - T - B) * (1 - g / 5);
    svg += `<line x1="${L}" x2="${W - 4}" y1="${y}" y2="${y}" stroke="var(--grid)"/><text x="${L - 6}" y="${y + 4}" text-anchor="end">${Math.round(nice * g / 5)}</text>`; }
  keys.forEach((k, i) => { const x = L + 8 + i * ((W - L - 10) / keys.length); let y0 = H - B;
    series.forEach(s => { const v = val(k, s); if (!v) return; const h = (H - T - B) * v / nice;
      svg += `<rect x="${x}" y="${y0 - h + 1}" width="${bw}" height="${Math.max(h - 2, 1)}" rx="3" fill="var(${colorOf(s)})" data-tip="${esc(`<b>${opts.keyLabel(k)}</b><br>${s}: ${v}`)}"/>`; y0 -= h; });
    svg += `<text x="${x + bw / 2}" y="${H - 8}" text-anchor="middle">${esc(opts.keyLabel(k))}</text>`; });
  el.innerHTML = svg + "</svg>";
  return series;
}
const hourKey = s => s.slice(0, 13);
const aser = stackedBars($("#achart"), M.alerts_fired, a => hourKey(a.start), a => a.rule, s => RULE_COLORS[s],
  {label: "Alerts fired per hour by rule", keyLabel: k => new Date(k + ":00:00Z").toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"})});
$("#alegend").innerHTML = aser.map(s => `<span style="--c:var(${RULE_COLORS[s]})">${esc(s)}</span>`).join("");
const grouped = {};
M.alerts_fired.forEach(a => { const k = a.rule + "|" + hourKey(a.start); (grouped[k] = grouped[k] || {...a, n: 0}).n++; });
$("#alerts").innerHTML = "<tr><th>First fired</th><th>Rule</th><th>#</th><th>Triage</th></tr>" + Object.values(grouped).map(a =>
  `<tr><td>${fmtT(a.start)}</td><td>${esc(a.rule)}</td><td>${a.n}</td><td>${a.disposition === "Untriaged" ? st("bad", "!", "Untriaged") : st("ok", "✓", a.disposition)}<div class="small muted">${esc(a.note)}</div></td></tr>`).join("");

// ---- activity per hour by category
const CAT_COLORS = {Administrative: "--s1", Alert: "--s2", Policy: "--s3", Security: "--s4"};
const hser = stackedBars($("#hchart"), M.activity_hourly, r => hourKey(r.TimeGenerated), r => r.Category, s => CAT_COLORS[s] || "--s4",
  {label: "Activity log events per hour", value: r => r.Events, keyLabel: k => new Date(k + ":00:00Z").toLocaleTimeString([], {hour:"2-digit", minute:"2-digit"})});
$("#hlegend").innerHTML = hser.map(s => `<span style="--c:var(${CAT_COLORS[s] || "--s4"})">${esc(s)}</span>`).join("");

// ---- security changes (horizontal bars, single hue = magnitude)
const chg = [...M.security_changes].sort((a, b) => b.Count - a.Count), cmax = Math.max(1, ...chg.map(c => c.Count));
$("#chg").innerHTML = chg.length ? chg.map(c => `<div style="display:grid;grid-template-columns:200px 1fr 34px;gap:8px;align-items:center;margin:5px 0">
  <span class="small">${esc(c.Kind)}</span><div class="bar"><b style="width:${100 * c.Count / cmax}%;background:var(--s1)" data-tip="${esc(`${c.Kind}: ${c.Count}<br>last ${fmtT(c.Last)}`)}"></b></div>
  <span class="small" style="text-align:right">${c.Count}</span></div>`).join("") : `<div class="muted">No security-relevant changes.</div>`;
$("#callers").innerHTML = "<tr><th>Caller</th><th>Type</th><th>Operations</th><th>Failed</th></tr>" + M.callers.map(c =>
  `<tr><td>${esc(c.Caller)}</td><td>${esc(c.Type)}</td><td>${c.Operations}</td><td>${c.Failed}</td></tr>`).join("");

// ---- incidents
$("#inc").innerHTML = inc.length ? `<div class="scroll"><table><tr><th>#</th><th>Title</th><th>Severity</th><th>Status</th><th>Created</th><th>Time to close</th></tr>${inc.map(i =>
  `<tr><td>${esc(i.IncidentNumber)}</td><td>${esc(i.Title)}</td><td>${esc(i.Severity)}</td><td>${i.Status === "Closed" ? st("ok", "✓", "Closed") : st("warn", "!", i.Status)}</td><td>${fmtT(i.CreatedTime)}</td><td>${i.MinutesToClose ? esc(i.MinutesToClose) + " min" : "—"}</td></tr>`).join("")}</table></div>`
  : `<div class="muted">No Sentinel incidents yet. Incidents appear here when an analytics rule matches (Step 4 playbook tests).</div>`;
const rows = [...M.alert_rules.map(r => ({n: r.name, k: "Activity-log alert", s: "—", e: r.enabled})), ...M.analytics_rules.map(r => ({n: r.name, k: "Sentinel " + r.kind, s: r.severity || "per alert", e: r.enabled}))];
$("#rules").innerHTML = "<tr><th>Rule</th><th>Type</th><th>Severity</th><th>Status</th></tr>" + rows.map(r =>
  `<tr><td>${esc(r.n)}</td><td class="muted">${esc(r.k)}</td><td>${esc(r.s)}</td><td>${r.e ? st("ok", "✓", "Enabled") : st("bad", "✕", "Disabled")}</td></tr>`).join("");

// ---- posture
const ss = M.secure_score, rec = M.recommendations;
$("#posture").innerHTML = (ss ? `<div style="display:flex;align-items:baseline;gap:10px"><span style="font-size:28px;font-weight:650">${ss.pct}%</span><span class="muted">secure score · ${ss.current} / ${ss.max}</span></div>
  <div class="bar" style="margin:6px 0 10px"><b style="width:${ss.pct}%;background:var(--s1)" data-tip="Secure score ${ss.pct}%"></b></div>` : "") +
  `<div class="small muted" style="margin-bottom:6px">${rec.healthy} healthy · ${rec.unhealthy.length} unhealthy · ${rec.not_applicable} not applicable. Defender re-evaluates about every 24 h, so items fixed in Step 2 may still be listed.</div>
  <table><tr><th>Open recommendation</th><th>Status</th></tr>${rec.unhealthy.map(r => `<tr><td>${esc(r)}</td><td>${st("bad", "!", "Unhealthy")}</td></tr>`).join("")}</table>`;

// ---- cost
if (!M.cost) { $("#cost").innerHTML = `<div class="muted">Cost Management did not return data on this run (the API is rate-limited). Re-run collect_metrics.py; no figure is shown rather than a false $0.</div>`; }
else {
const cmax2 = Math.max(1, ...M.cost.by_type.map(c => c.usd));
$("#cost").innerHTML = `<div style="display:flex;align-items:baseline;gap:10px"><span style="font-size:28px;font-weight:650">$${M.cost.total.toFixed(2)}</span><span class="muted">of $${M.cost.credit} free-trial credit · spending limit on, no card charge</span></div>
  <div class="bar" style="margin:6px 0 12px"><b style="width:${100 * M.cost.total / M.cost.credit}%;background:var(--s1)" data-tip="${(100 * M.cost.total / M.cost.credit).toFixed(1)}% of credit used"></b></div>` +
  M.cost.by_type.map(c => `<div style="display:grid;grid-template-columns:150px 1fr 60px;gap:8px;align-items:center;margin:4px 0"><span class="small">${esc(c.type)}</span>
  <div class="bar"><b style="width:${100 * c.usd / cmax2}%;background:var(--s1)" data-tip="${esc(c.type)}: $${c.usd.toFixed(2)}"></b></div><span class="small" style="text-align:right">$${c.usd.toFixed(2)}</span></div>`).join("") +
  `<div class="small muted" style="margin-top:8px">All credit use comes from the pre-existing Bastion, NAT gateway and public IPs. Security-operations tooling (workspace, alerts, Defender and Sentinel trials) has cost $0.00 so far. Cost data can lag by up to 24 h.</div>`;
}
</script></body></html>'''

if __name__ == "__main__":
    main()
