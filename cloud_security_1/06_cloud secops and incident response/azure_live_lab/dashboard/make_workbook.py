"""Generate the Azure Workbook definition (hvmc_secops_workbook.json) from workbook_queries.TILES."""
import json
import os
import sys

from workbook_queries import TILES

HERE = os.path.dirname(os.path.abspath(__file__))


def workbook(law_id):
    items = [
        {"type": 1, "name": "title", "content": {"json": "## HVMC Security Operations\n"
         "Horizon Valley Medical Center · centralised logging (Activity Log, NSG, Bastion, ePHI storage, VNet flow logs), "
         "Defender for Cloud and Microsoft Sentinel in **HVMC-SecOps-LAW**. Author: Sabitha S Karanavar."}},
        {"type": 9, "name": "parameters", "content": {"version": "KqlParameterItem/1.0", "style": "pills", "queryType": 0,
         "resourceType": "microsoft.operationalinsights/workspaces", "parameters": [
             {"id": "8f1c3a52-0d7e-4b8e-9b51-6c2d1f0a7e11", "version": "KqlParameterItem/1.0", "name": "TimeRange", "label": "Time range",
              "type": 4, "isRequired": True, "value": {"durationMs": 604800000},
              "typeSettings": {"selectableValues": [{"durationMs": 3600000}, {"durationMs": 86400000}, {"durationMs": 604800000},
                                                    {"durationMs": 2592000000}], "allowCustom": True}}]}},
    ]
    for i, (title, query, viz, width) in enumerate(TILES):
        items.append({"type": 3, "name": f"tile{i + 1}", "customWidth": str(width), "content": {
            "version": "KqlItem/1.0", "query": query, "size": 1, "title": title, "timeContextFromParameter": "TimeRange",
            "queryType": 0, "resourceType": "microsoft.operationalinsights/workspaces", "crossComponentResources": [law_id],
            "visualization": viz, "noDataMessage": "No events in this time range"}})
    return {"version": "Notebook/1.0", "items": items, "fallbackResourceIds": [law_id],
            "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"}


if __name__ == "__main__":
    law_id = sys.argv[1]
    out = os.path.join(HERE, "hvmc_secops_workbook.json")
    json.dump(workbook(law_id), open(out, "w"), indent=1)
    print(out)
