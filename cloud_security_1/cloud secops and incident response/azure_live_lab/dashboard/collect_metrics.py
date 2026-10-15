"""
HVMC security operations metrics collector - read-only, $0.

Horizon Valley Medical Center - Cloud Security Operations & Incident Response
Author: Sabitha S Karanavar

Pulls the dashboard's key metrics from the live environment with read-only Azure CLI / KQL calls
(Log Analytics queries, Sentinel, Defender for Cloud, Azure Monitor alerts, Cost Management) and
writes metrics.json next to this file. Nothing in Azure is created or changed.

    python3 collect_metrics.py           # then: python3 build_dashboard.py
"""
import datetime as dt
import json
import os
import shutil
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
AZ = shutil.which("az") or os.path.expanduser("~/.azure-cli-env/bin/az")
RG, LAW = "HVMC-CloudSecurity-RG", "HVMC-SecOps-LAW"
TRIAL_END = "2026-10-17T16:01:44Z"
ARM = "https://management.azure.com"


def az(*args):
    env = dict(os.environ, PYTHONWARNINGS="ignore", AZURE_CORE_ONLY_SHOW_ERRORS="true")
    p = subprocess.run([AZ, *args, "-o", "json"], capture_output=True, text=True, env=env)
    if p.returncode:
        raise RuntimeError(f"az {' '.join(args[:3])}: {p.stderr.strip().splitlines()[-1] if p.stderr.strip() else 'failed'}")
    return json.loads(p.stdout or "null")


def safe(fn, default):
    try:
        return fn()
    except Exception as e:                       # a missing table or API must not break the dashboard
        print("  warn:", str(e)[:160])
        return default


SUB = az("account", "show")["id"]
WS = az("monitor", "log-analytics", "workspace", "show", "-g", RG, "-n", LAW)
WSID = WS["customerId"]


def kql(q, span="P7D"):
    return az("monitor", "log-analytics", "query", "-w", WSID, "--analytics-query", q, "-t", span)


def rest(url):
    return az("rest", "--method", "get", "--url", url)


def collect():
    m = dict(generated=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), subscription=SUB[:8] + "…",
             workspace=LAW, trial_end=TRIAL_END)

    # ---- 1. logging coverage (is every source connected?)
    def diag(res_id):
        return [l["category"] for s in az("monitor", "diagnostic-settings", "list", "--resource", res_id) for l in s.get("logs", []) if l.get("enabled")]
    sub_diag = az("monitor", "diagnostic-settings", "subscription", "list")
    sub_diag = sub_diag.get("value", sub_diag) if isinstance(sub_diag, dict) else sub_diag
    act = [l["category"] for s in sub_diag for l in s.get("logs", []) if l.get("enabled")]
    cov = [dict(source="Activity Log (CloudTrail equivalent)", detail=f"{len(act)} of 8 categories", ok=len(act) == 8)]
    for n in ("HVMC-Web-NSG", "HVMC-App-NSG", "HVMC-Data-NSG"):
        c = diag(az("network", "nsg", "show", "-g", RG, "-n", n)["id"])
        cov.append(dict(source=f"{n} events", detail=", ".join(c) or "none", ok=bool(c)))
    c = diag(az("network", "bastion", "show", "-g", RG, "-n", "HVMC-Bastion")["id"])
    cov.append(dict(source="Bastion session audit", detail=", ".join(c) or "none", ok=bool(c)))
    c = diag(az("storage", "account", "show", "-g", RG, "-n", "hvmcehrstorage")["id"] + "/blobServices/default")
    cov.append(dict(source="ePHI blob access (hvmcehrstorage)", detail=", ".join(c) or "none", ok=len(c) == 3))
    fl = safe(lambda: az("network", "watcher", "flow-log", "show", "--location", "eastus", "-n", "HVMC-Prod-VNet-FlowLog"), {})
    ta = (fl.get("flowAnalyticsConfiguration") or {}).get("networkWatcherFlowAnalyticsConfiguration") or {}
    cov.append(dict(source="VNet flow logs (VPC Flow Logs equivalent)", detail=f"retention {fl.get('retentionPolicy', {}).get('days')} d, Traffic Analytics {'on' if ta.get('enabled') else 'off'}",
                    ok=bool(fl.get("enabled"))))
    plans = {p["name"]: p for p in az("security", "pricing", "list")["value"]}
    for key, label in (("StorageAccounts", "Defender for Storage"), ("Arm", "Defender for Resource Manager")):
        p = plans.get(key, {})
        cov.append(dict(source=label, detail=f"{p.get('pricingTier')} · trial left {p.get('freeTrialRemainingTime')}", ok=p.get("pricingTier") == "Standard"))
    si = f"{ARM}{WS['id']}/providers/Microsoft.SecurityInsights"
    onb = safe(lambda: rest(f"{si}/onboardingStates?api-version=2024-03-01")["value"], [])
    cov.append(dict(source="Microsoft Sentinel (SIEM)", detail="onboarded" if onb else "not onboarded", ok=bool(onb)))
    cov.append(dict(source="Entra ID sign-in / audit logs", detail="needs Entra ID P1/P2 licence - known gap (R12)", ok=False, gap=True))
    m["coverage"] = cov

    # ---- 2. detection rules
    al = az("monitor", "activity-log", "alert", "list", "-g", RG)
    m["alert_rules"] = [dict(name=a["name"], enabled=a["enabled"]) for a in al]
    rules = safe(lambda: rest(f"{si}/alertRules?api-version=2024-03-01")["value"], [])
    m["analytics_rules"] = [dict(name=r["properties"]["displayName"], kind=r["kind"], severity=r["properties"].get("severity"),
                                 enabled=r["properties"]["enabled"]) for r in rules]

    # ---- 3. alerts fired (Azure Monitor) - last 7 days
    fired = safe(lambda: rest(f"{ARM}/subscriptions/{SUB}/providers/Microsoft.AlertsManagement/alerts?api-version=2019-05-05-preview&timeRange=7d")["value"], [])
    m["alerts_fired"] = sorted([dict(rule=a["name"], severity=a["properties"]["essentials"]["severity"], state=a["properties"]["essentials"]["alertState"],
                                     condition=a["properties"]["essentials"].get("monitorCondition"), start=a["properties"]["essentials"]["startDateTime"])
                                for a in fired], key=lambda a: a["start"], reverse=True)

    # ---- 4. Sentinel incidents and Defender alerts (tables appear after the first event)
    inc = safe(lambda: kql("""union isfuzzy=true SecurityIncident, (datatable(IncidentNumber:int)[])
| summarize arg_max(TimeGenerated, *) by IncidentNumber | where isnotempty(Title)
| project IncidentNumber, Title, Severity, Status, Classification, CreatedTime, FirstModifiedTime, ClosedTime,
          MinutesToTriage = datetime_diff('minute', FirstModifiedTime, CreatedTime), MinutesToClose = datetime_diff('minute', ClosedTime, CreatedTime)""", "P30D"), [])
    m["incidents"] = inc
    m["defender_alerts"] = safe(lambda: kql("""union isfuzzy=true SecurityAlert, (datatable(SystemAlertId:string)[])
| where isnotempty(AlertName) | summarize arg_max(TimeGenerated, *) by SystemAlertId
| project TimeGenerated, AlertName, AlertSeverity, ProductName, Status, CompromisedEntity""", "P30D"), [])

    # ---- 5. control-plane activity
    m["activity_hourly"] = safe(lambda: kql("""AzureActivity | where TimeGenerated > ago(48h)
| summarize Events = count() by bin(TimeGenerated, 1h), Category = CategoryValue | order by TimeGenerated asc""", "P2D"), [])
    m["security_changes"] = safe(lambda: kql("""AzureActivity | where ActivityStatusValue in~ ('Success','Succeeded')
| extend Kind = case(
    OperationNameValue has 'securityRules', 'Firewall (NSG) rule change',
    OperationNameValue has 'roleAssignments', 'Role assignment change',
    OperationNameValue has 'listKeys' or OperationNameValue has 'regenerateKey', 'Storage key access',
    OperationNameValue =~ 'MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE', 'Storage configuration change',
    OperationNameValue has 'publicIPAddresses/write', 'Public IP created',
    OperationNameValue has 'diagnosticSettings/delete' or OperationNameValue has 'flowLogs/delete', 'Logging disabled',
    OperationNameValue has 'Microsoft.Security/pricings', 'Defender plan change',
    '')
| where isnotempty(Kind) | summarize Count = count(), Last = max(TimeGenerated) by Kind""", "P7D"), [])
    m["callers"] = safe(lambda: kql("""AzureActivity | where isnotempty(Caller)
| extend Type = iff(Caller has '@', 'User', 'Service principal')
| summarize Operations = count(), Failed = countif(ActivityStatusValue =~ 'Failure' or ActivityStatusValue =~ 'Failed') by Caller, Type
| top 8 by Operations""", "P7D"), [])
    for c in m["callers"]:                       # show service principals by name, not object id
        if c.get("Type") == "Service principal":
            c["Caller"] = safe(lambda: az("ad", "sp", "show", "--id", c["Caller"])["displayName"], c["Caller"]) + " (Microsoft service)"
    m["failed_ops"] = safe(lambda: kql("""AzureActivity | where ActivityStatusValue in~ ('Failure','Failed') | summarize n = count()""", "P7D"), [{"n": 0}])[0]["n"]
    m["epHI_access"] = safe(lambda: kql("""union isfuzzy=true StorageBlobLogs, (datatable(OperationName:string)[])
| where isnotempty(OperationName) | summarize Requests = count(), Callers = dcount(CallerIpAddress) by OperationName""", "P7D"), [])
    m["flows"] = safe(lambda: kql("""union isfuzzy=true NTANetAnalytics, (datatable(FlowStatus:string)[])
| where isnotempty(FlowStatus) | summarize Flows = count() by FlowStatus""", "P7D"), [])

    # ---- 6. ingestion vs the 0.5 GB/day cap
    m["ingestion"] = safe(lambda: kql("""Usage | where TimeGenerated > ago(7d) | summarize MB = round(sum(Quantity), 3) by DataType | order by MB desc""", "P7D"), [])
    m["daily_cap_gb"] = (WS.get("workspaceCapping") or {}).get("dailyQuotaGb")

    # ---- 7. posture: Defender secure score + recommendations
    ss = safe(lambda: az("security", "secure-scores", "list"), [])
    m["secure_score"] = dict(current=ss[0]["current"], max=ss[0]["max"], pct=round(ss[0]["percentage"] * 100)) if ss else None
    asm = safe(lambda: rest(f"{ARM}/subscriptions/{SUB}/providers/Microsoft.Security/assessments?api-version=2021-06-01")["value"], [])
    m["recommendations"] = dict(healthy=sum(a["properties"]["status"]["code"] == "Healthy" for a in asm),
                                unhealthy=[a["properties"]["displayName"] for a in asm if a["properties"]["status"]["code"] == "Unhealthy"],
                                not_applicable=sum(a["properties"]["status"]["code"] == "NotApplicable" for a in asm))

    # ---- 8. cost (credit use) - the user asked to be told about every charge
    def cost(frm, to, group=True):
        body = {"type": "ActualCost", "timeframe": "Custom", "timePeriod": {"from": frm, "to": to},
                "dataset": {"granularity": "None", "aggregation": {"c": {"name": "Cost", "function": "Sum"}}}}
        if group:
            body["dataset"]["grouping"] = [{"type": "Dimension", "name": "ResourceType"}]
        return az("rest", "--method", "post", "--url", f"{ARM}/subscriptions/{SUB}/providers/Microsoft.CostManagement/query?api-version=2023-11-01",
                  "--body", json.dumps(body))["properties"]["rows"]
    today = dt.date.today().isoformat()
    rows = None
    for attempt in range(3):                     # Cost Management throttles (429); never report $0 for "no data"
        rows = safe(lambda: cost("2026-09-17", today), None)
        if rows:
            break
        time.sleep(20)
    cache = os.path.join(HERE, "cost_cache.json")
    if not rows:                                  # throttled: reuse the last good figure, clearly dated
        m["cost"] = json.load(open(cache)) if os.path.exists(cache) else None
        if m["cost"]:
            m["cost"]["stale"] = True
        return m
    m["cost"] = dict(credit=200.0, total=round(sum(r[0] for r in rows), 2), as_of=m["generated"], stale=False,
                     by_type=sorted([dict(type=r[1].split("/")[-1], usd=round(r[0], 2)) for r in rows], key=lambda x: -x["usd"]))
    json.dump(m["cost"], open(cache, "w"), indent=1)
    return m


if __name__ == "__main__":
    data = collect()
    with open(os.path.join(HERE, "metrics.json"), "w") as f:
        json.dump(data, f, indent=1, default=str)
    print("metrics.json written:", {k: (len(v) if isinstance(v, list) else v) for k, v in data.items() if k not in ("cost", "recommendations")})
