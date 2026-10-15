"""KQL tiles for the HVMC SecOps Azure Workbook - shared by make_workbook.py and the test run."""
SECURITY_KIND = """case(
    OperationNameValue has 'securityRules', 'Firewall (NSG) rule change',
    OperationNameValue has 'roleAssignments', 'Role assignment change',
    OperationNameValue has 'listKeys' or OperationNameValue has 'regenerateKey', 'Storage key access',
    OperationNameValue =~ 'MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE', 'Storage configuration change',
    OperationNameValue has 'publicIPAddresses/write', 'Public IP created',
    OperationNameValue has 'diagnosticSettings/delete' or OperationNameValue has 'flowLogs/delete', 'Logging disabled',
    OperationNameValue has 'Microsoft.Security/pricings', 'Defender plan change', '')"""

# (title, query, visualization, width%)
TILES = [
    ("Log sources reporting (events per table)",
     "union withsource=LogTable * | where TimeGenerated {TimeRange} | summarize Events = count(), LastEvent = max(TimeGenerated) by LogTable | order by Events desc",
     "table", 50),
    ("Security alerts fired (Azure Monitor activity-log alerts)",
     "AzureActivity | where TimeGenerated {TimeRange} | where OperationNameValue has 'ActivityLogAlerts/Activated'\n"
     "| extend Rule = tostring(split(_ResourceId, '/')[-1]) | summarize Fired = count() by Rule | order by Fired desc",
     "barchart", 50),
    ("Control-plane activity per hour by category",
     "AzureActivity | where TimeGenerated {TimeRange} | summarize Events = count() by bin(TimeGenerated, 1h), CategoryValue",
     "timechart", 50),
    ("Security-relevant changes",
     "AzureActivity | where TimeGenerated {TimeRange} | where ActivityStatusValue in~ ('Success','Succeeded')\n"
     "| extend Kind = " + SECURITY_KIND + "\n| where isnotempty(Kind) | summarize Count = count(), Last = max(TimeGenerated) by Kind | order by Count desc",
     "table", 50),
    ("Who is making changes",
     "AzureActivity | where TimeGenerated {TimeRange} | where isnotempty(Caller)\n"
     "| summarize Operations = count(), Failed = countif(ActivityStatusValue in~ ('Failure','Failed')) by Caller | top 10 by Operations",
     "table", 50),
    ("Sentinel incidents by severity and status",
     "union isfuzzy=true SecurityIncident, (datatable(IncidentNumber:int, Severity:string, Status:string, TimeGenerated:datetime)[])\n"
     "| where TimeGenerated {TimeRange} | summarize arg_max(TimeGenerated, *) by IncidentNumber | where isnotempty(Severity)\n"
     "| summarize Incidents = count() by Severity, Status",
     "table", 50),
    ("Defender for Cloud alerts",
     "union isfuzzy=true SecurityAlert, (datatable(AlertName:string, AlertSeverity:string, ProductName:string, TimeGenerated:datetime)[])\n"
     "| where TimeGenerated {TimeRange} | where isnotempty(AlertName) | summarize Alerts = count() by AlertName, AlertSeverity, ProductName",
     "table", 50),
    ("ePHI storage access (hvmcehrstorage blob operations)",
     "union isfuzzy=true StorageBlobLogs, (datatable(OperationName:string, CallerIpAddress:string, StatusText:string, TimeGenerated:datetime)[])\n"
     "| where TimeGenerated {TimeRange} | where isnotempty(OperationName)\n"
     "| summarize Requests = count(), DistinctCallers = dcount(CallerIpAddress), Failures = countif(StatusText != 'Success') by OperationName",
     "table", 50),
    ("Network flows (VNet flow logs / Traffic Analytics)",
     "union isfuzzy=true NTANetAnalytics, (datatable(FlowStatus:string, FlowDirection:string, TimeGenerated:datetime)[])\n"
     "| where TimeGenerated {TimeRange} | where isnotempty(FlowStatus) | summarize Flows = count() by FlowStatus, FlowDirection",
     "table", 50),
    ("Log ingestion vs 0.5 GB/day cap (MB per day)",
     "Usage | where TimeGenerated {TimeRange} | summarize MB = sum(Quantity) by bin(TimeGenerated, 1d), DataType",
     "barchart", 50),
]
