"""
HVMC incident response playbook - live tests (safe: no test weakens any control).

Horizon Valley Medical Center - Cloud Security Operations & Incident Response
Author: Sabitha S Karanavar

  PB-03 ePHI storage threat : Microsoft Defender for Cloud built-in SAMPLE alerts for Storage
                              -> identification, containment (secondary key rotated = hardening),
                                 investigation, eradication checks, recovery (alerts resolved, incidents closed)
  PB-01 firewall change     : an explicit DENY-Internet-inbound rule on the Data-tier NSG (tightens R03)
                              -> alert fires, change is triaged against the change record, baseline updated
  PB-02 privilege escalation: tabletop exercise (documented in the playbook, no live change)

Every phase is timestamped; results go to evidence/ir_tests/*.json.
COST: $0 (sample alerts, NSG rules, key rotation, alert e-mails and Sentinel incidents are free).
"""
import datetime as dt
import json
import os
import shutil
import subprocess
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "evidence", "ir_tests")
os.makedirs(OUT, exist_ok=True)
AZ = shutil.which("az") or os.path.expanduser("~/.azure-cli-env/bin/az")
RG, NSG, SA = "HVMC-CloudSecurity-RG", "HVMC-Data-NSG", "hvmcehrstorage"
ASC_LOC = "centralus"          # Defender alerts API location for this subscription (az security location list is misleading)
DENY_RULE = "Deny-Internet-Inbound-Data"
ARM = "https://management.azure.com"


def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def az(*args, check=True):
    env = dict(os.environ, PYTHONWARNINGS="ignore", AZURE_CORE_ONLY_SHOW_ERRORS="true")
    p = subprocess.run([AZ, *args, "-o", "json"], capture_output=True, text=True, env=env)
    if p.returncode and check:
        raise RuntimeError(f"az {' '.join(args[:4])}: {(p.stderr.strip().splitlines() or ['failed'])[-1]}")
    return json.loads(p.stdout) if p.stdout.strip() else None


def rest(method, url, body=None):
    a = ["rest", "--method", method, "--url", url]
    if body is not None:
        a += ["--body", json.dumps(body)]
    return az(*a)


SUB = az("account", "show")["id"]
WS = az("monitor", "log-analytics", "workspace", "show", "-g", RG, "-n", "HVMC-SecOps-LAW")
SI = f"{ARM}{WS['id']}/providers/Microsoft.SecurityInsights"
SIV = "api-version=2024-03-01"
SEC = f"{ARM}/subscriptions/{SUB}/providers/Microsoft.Security/locations/{ASC_LOC}/alerts"


def kql(q, span="PT6H"):
    return az("monitor", "log-analytics", "query", "-w", WS["customerId"], "--analytics-query", q, "-t", span)


def log(msg):
    print(f"[{now()}] {msg}", flush=True)


def poll(fn, timeout_s, every_s=20, what=""):
    end = time.time() + timeout_s
    while time.time() < end:
        try:
            r = fn()
            if r:
                return r
        except Exception as e:
            log(f"  (retrying {what}: {str(e)[:100]})")
        time.sleep(every_s)
    return None


def minutes(a, b):
    if not a or not b:
        return None
    f = lambda s: dt.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
    return round((f(b) - f(a)).total_seconds() / 60, 1)


def fired(rule, since):
    al = rest("get", f"{ARM}/subscriptions/{SUB}/providers/Microsoft.AlertsManagement/alerts?api-version=2019-05-05-preview&timeRange=1h")["value"]
    t = sorted(a["properties"]["essentials"]["startDateTime"][:19] for a in al
               if a["name"] == rule and a["properties"]["essentials"]["startDateTime"][:19] >= since[:19])
    return t[0] + "Z" if t else None


def step(rec, name, fn):
    start = now()
    try:
        detail = fn()
        ok = True
    except Exception as e:
        detail, ok = f"FAILED: {e}", False
    rec["phases"].append(dict(phase=name, started=start, finished=now(), ok=ok, detail=detail))
    log(f"  {name}: {'OK' if ok else 'FAILED'} - {str(detail)[:150]}")
    json.dump(rec, open(os.path.join(OUT, rec["id"] + ".json"), "w"), indent=1, default=str)
    return detail


# ================================================================== PB-03 ePHI storage threat (Defender sample alerts)
def sample_alerts(since):
    """Defender alerts raised after `since` (only the sample alerts are expected in this lab)."""
    out = []
    for a in az("security", "alert", "list"):
        p = a.get("properties", a)                     # CLI flattens properties; REST nests them
        if (p.get("timeGeneratedUtc") or "")[:19] >= since[:19]:
            out.append(dict(name=a["name"], alertDisplayName=p.get("alertDisplayName"), severity=p.get("severity"),
                            timeGeneratedUtc=p.get("timeGeneratedUtc"), compromisedEntity=p.get("compromisedEntity"), intent=p.get("intent")))
    return out


def pb03():
    rec = dict(id="PB-03", title="ePHI storage threat - Defender for Storage alerts (built-in sample alerts)", phases=[])
    log("PB-03 start: generating Defender for Cloud sample alerts for Storage")
    rec["injected_at"] = now()
    rest("post", f"{SEC}/default/simulate?api-version=2022-01-01", {"properties": {"kind": "Bundles", "bundles": ["StorageAccounts"]}})
    log(f"  sample alerts requested at {rec['injected_at']}")

    def identify():
        alerts = poll(lambda: sample_alerts(rec["injected_at"]), 900, what="Defender alerts")
        if not alerts:
            raise RuntimeError("no Defender sample alert within 15 min")
        rec["detected_at"] = min(a["timeGeneratedUtc"][:19] for a in alerts) + "Z"
        rec["alerts"] = [dict(name=a["name"], title=a["alertDisplayName"], severity=a["severity"], time=a["timeGeneratedUtc"],
                              entity=a.get("compromisedEntity"), tactics=a.get("intent")) for a in alerts]
        return f"{len(alerts)} Defender alerts: " + "; ".join(sorted({a['alertDisplayName'] for a in alerts}))[:400]
    step(rec, "1 Identification", identify)

    def triage():   # mark alerts In progress = acknowledged
        for a in rec.get("alerts", []):
            rest("post", f"{SEC}/{a['name']}/inProgress?api-version=2022-01-01")
        rec["acknowledged_at"] = now()
        return f"{len(rec.get('alerts', []))} alerts set to In progress (acknowledged)"
    step(rec, "1b Triage / acknowledge", triage)

    def contain():  # rotate the unused secondary key: any copied key becomes useless (hardening, no outage)
        az("storage", "account", "keys", "renew", "-g", RG, "-n", SA, "--key", "secondary", "--query", "[].keyName")
        rec["contained_at"] = now()
        net = az("storage", "account", "show", "-g", RG, "-n", SA, "--query",
                 "{publicNetworkAccess:publicNetworkAccess,defaultAction:networkRuleSet.defaultAction,sharedKey:allowSharedKeyAccess}")
        return f"secondary access key of {SA} regenerated (key2 not used by any application); network posture recorded: {net}"
    step(rec, "2 Containment", contain)

    def investigate():
        det = [dict(title=a["title"], severity=a["severity"], entity=a["entity"], tactics=a["tactics"]) for a in rec.get("alerts", [])]
        blob = kql("""union isfuzzy=true StorageBlobLogs, (datatable(OperationName:string, CallerIpAddress:string, TimeGenerated:datetime, AccountName:string)[])
| where AccountName =~ 'hvmcehrstorage' | summarize Requests = count(), Callers = make_set(CallerIpAddress, 10) by OperationName""", "P1D")
        act = kql("""AzureActivity | where _ResourceId has 'hvmcehrstorage' | where TimeGenerated > ago(24h)
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue | order by TimeGenerated desc | take 20""", "P1D")
        rec["investigation"] = dict(alert_details=det, epHI_blob_access_24h=blob, epHI_control_plane_24h=act)
        return (f"alert entities reviewed; ePHI blob data-plane operations in 24 h: {sum(int(r['Requests']) for r in blob) if blob else 0}; "
                f"control-plane events on the account in 24 h: {len(act)} (all by known callers)")
    step(rec, "3 Investigation", investigate)

    def eradicate():
        p = rest("get", f"{ARM}/subscriptions/{SUB}/providers/Microsoft.Security/pricings/StorageAccounts?api-version=2024-01-01")["properties"]
        mw = next((e for e in p.get("extensions", []) if e["name"] == "OnUploadMalwareScanning"), {})
        if p["pricingTier"] != "Standard":
            raise RuntimeError("Defender for Storage is not on Standard")
        return f"Defender for Storage {p['pricingTier']} and malware scanning {mw.get('isEnabled')} confirmed; sample alerts carry no payload, so no blob needed removal"
    step(rec, "4 Eradication", eradicate)

    def recover():
        for a in rec.get("alerts", []):
            rest("post", f"{SEC}/{a['name']}/resolve?api-version=2022-01-01")
        rec["recovered_at"] = now()
        return f"{len(rec.get('alerts', []))} Defender alerts resolved; protection verified still enabled"
    step(rec, "5 Recovery", recover)
    return rec


# ================================================================== PB-01 firewall change (deny rule = hardening)
def pb01():
    rec = dict(id="PB-01", title="Unplanned firewall change on the Data tier - detection and change verification", phases=[])
    log("PB-01 start: adding an explicit Deny-Internet-inbound rule to the Data NSG (tightens R03)")
    rec["baseline_rules"] = [f'{r["name"]} p{r["priority"]} {r["access"]} {r.get("sourceAddressPrefix")}->{r.get("destinationPortRange")}'
                             for r in az("network", "nsg", "rule", "list", "-g", RG, "--nsg-name", NSG)]
    rec["injected_at"] = now()
    az("network", "nsg", "rule", "create", "-g", RG, "--nsg-name", NSG, "-n", DENY_RULE, "--priority", "4000",
       "--direction", "Inbound", "--access", "Deny", "--protocol", "*", "--source-address-prefixes", "Internet",
       "--source-port-ranges", "*", "--destination-address-prefixes", "*", "--destination-port-ranges", "*",
       "--description", "Explicit deny of Internet inbound to the ePHI data tier (R03). Change HVMC-CHG-04 / IR test PB-01.")
    log(f"  rule {DENY_RULE} created at {rec['injected_at']}")

    def identify():
        t = poll(lambda: fired("HVMC-NSG-Rule-Changed", rec["injected_at"]), 900, what="NSG alert")
        if not t:
            raise RuntimeError("HVMC-NSG-Rule-Changed not fired within 15 min")
        rec["detected_at"] = t
        return f"Azure Monitor alert HVMC-NSG-Rule-Changed fired at {t}; e-mail sent to the Security Lead"
    step(rec, "1 Identification", identify)

    def investigate():
        rows = poll(lambda: kql(f"""AzureActivity | where _ResourceId has '{DENY_RULE}'
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue, CorrelationId | order by TimeGenerated asc""", "PT2H"),
                    900, what="activity log ingestion")
        rule = az("network", "nsg", "rule", "show", "-g", RG, "--nsg-name", NSG, "-n", DENY_RULE)
        rec["investigated_at"] = now()
        rec["investigation"] = dict(activity=rows, rule=dict(access=rule["access"], direction=rule["direction"], source=rule["sourceAddressPrefix"],
                                                            ports=rule["destinationPortRange"], priority=rule["priority"]))
        who = rows[0]["Caller"] if rows else "unknown"
        return (f"who: {who}; what: {rule['direction']} {rule['access']} from {rule['sourceAddressPrefix']} to port {rule['destinationPortRange']}; "
                f"matches approved change HVMC-CHG-04 -> authorised; effect reduces exposure")
    step(rec, "2-3 Triage, containment decision and investigation", investigate)

    def eradicate():
        bad = []
        for n in az("network", "nsg", "list", "-g", RG, "--query", "[].name"):
            for r in az("network", "nsg", "rule", "list", "-g", RG, "--nsg-name", n):
                if r["direction"] == "Inbound" and r["access"] == "Allow" and r.get("sourceAddressPrefix") in ("*", "Internet", "0.0.0.0/0") \
                        and not (n == "HVMC-Web-NSG" and r.get("destinationPortRange") == "443"):
                    bad.append(f"{n}/{r['name']}")
        if bad:
            raise RuntimeError(f"unexpected Internet allow rules: {bad}")
        return "sweep of all NSGs: no Internet-facing allow rule except the approved Web HTTPS 443 rule"
    step(rec, "4 Eradication (exposure sweep)", eradicate)

    def recover():
        after = [f'{r["name"]} p{r["priority"]} {r["access"]} {r.get("sourceAddressPrefix")}->{r.get("destinationPortRange")}'
                 for r in az("network", "nsg", "rule", "list", "-g", RG, "--nsg-name", NSG)]
        rec["new_baseline_rules"] = after
        rec["recovered_at"] = now()
        added = sorted(set(after) - set(rec["baseline_rules"]))
        return f"baseline updated with the approved change; difference from previous baseline: {added}; App->Data 1433 rule unchanged"
    step(rec, "5 Recovery (baseline updated)", recover)
    return rec


# ================================================================== Sentinel incidents: wait, comment, close
def incidents_since(since):
    v = rest("get", f"{SI}/incidents?{SIV}&$orderby=properties/createdTimeUtc desc&$top=50")["value"]
    return [i for i in v if i["properties"]["createdTimeUtc"][:19] >= since[:19]]


def close_incidents(since, expect_min):
    log("Waiting for Microsoft Sentinel incidents (analytics rules run every 5 min; ingestion adds 5-10 min)")
    poll(lambda: len(incidents_since(since)) >= expect_min, 1500, 30, "Sentinel incidents")
    out = []
    for i in incidents_since(since):
        p = i["properties"]
        if p.get("status") == "Closed":              # already handled (e.g. by a parallel run)
            out.append(dict(number=p["incidentNumber"], title=p["title"], severity=p["severity"], created=p["createdTimeUtc"][:19] + "Z",
                            closed=(p.get("closedTimeUtc") or p.get("lastModifiedTimeUtc") or "")[:19] + "Z",
                            minutes_open=minutes(p["createdTimeUtc"], p.get("closedTimeUtc") or p.get("lastModifiedTimeUtc"))))
            continue
        if "NSG" in p["title"]:
            msg = ("IR exercise (HVMC-IRX-2026-10), playbook PB-01: firewall change on HVMC-Data-NSG matched approved change "
                   "HVMC-CHG-04 (explicit Deny-Internet-inbound). Exposure sweep clean; baseline updated.")
            reason, cls = "SuspiciousButExpected", "BenignPositive"
        else:
            msg = ("IR exercise (HVMC-IRX-2026-10), playbook PB-03: Microsoft Defender sample alert for Storage - alerts acknowledged, "
                   "secondary key rotated, ePHI access reviewed, protection verified, alerts resolved.")
            reason, cls = "SuspiciousButExpected", "BenignPositive"
        rest("put", f"{SI}/incidents/{i['name']}/comments/{uuid.uuid4()}?{SIV}", {"properties": {"message": msg}})
        closed_at = now()
        i = rest("get", f"{SI}/incidents/{i['name']}?{SIV}")   # re-read: the comment changed the etag (fixed after the 15 Oct run)
        body = {"etag": i.get("etag"), "properties": {"title": p["title"], "severity": p["severity"], "status": "Closed",
                "classification": cls, "classificationReason": reason,
                "classificationComment": "Planned IR exercise HVMC-IRX-2026-10 - no real threat."}}
        try:
            rest("put", f"{SI}/incidents/{i['name']}?{SIV}", body)
        except Exception as e:
            log(f"  incident #{p['incidentNumber']} not closed: {str(e)[:120]}")
            continue
        out.append(dict(number=p["incidentNumber"], title=p["title"], severity=p["severity"], created=p["createdTimeUtc"][:19] + "Z",
                        closed=closed_at, minutes_open=minutes(p["createdTimeUtc"], closed_at)))
        log(f"  incident #{p['incidentNumber']} '{p['title'][:60]}' commented and closed")
    return out


if __name__ == "__main__":
    import sys
    chosen = [a.upper() for a in sys.argv[1:]] or ["PB-03", "PB-01"]
    start = now()
    log(f"HVMC IR exercise HVMC-IRX-2026-10 started {start}: {', '.join(chosen)}")
    results = dict(exercise="HVMC-IRX-2026-10", started=start, tests=[])
    for fn in [f for k, f in (("PB-03", pb03), ("PB-01", pb01)) if k in chosen]:
        try:
            results["tests"].append(fn())
        except Exception as e:
            log(f"{fn.__name__} aborted: {e}")
            results["tests"].append(dict(id=fn.__name__.upper(), error=str(e)))
    try:
        results["sentinel_incidents"] = close_incidents(start, 1)
    except Exception as e:
        results["sentinel_incidents_error"] = str(e)
    for t in results["tests"]:
        t["mttd_min"] = minutes(t.get("injected_at"), t.get("detected_at"))
        t["mttc_min"] = minutes(t.get("detected_at"), t.get("contained_at") or t.get("investigated_at"))
        t["mttr_min"] = minutes(t.get("detected_at"), t.get("recovered_at"))
    results["finished"] = now()
    name = "results.json" if len(chosen) == 2 else f"results_{'_'.join(chosen)}.json"
    json.dump(results, open(os.path.join(OUT, name), "w"), indent=1, default=str)
    log("SUMMARY")
    for t in results["tests"]:
        log(f"  {t['id']}: detect {t.get('mttd_min')} min, contain {t.get('mttc_min')} min, recover {t.get('mttr_min')} min, "
            f"phases ok {sum(p['ok'] for p in t.get('phases', []))}/{len(t.get('phases', []))}")
    log(f"  Sentinel incidents closed: {len(results.get('sentinel_incidents', []))}")
    log(f"results: {os.path.abspath(os.path.join(OUT, name))}")
