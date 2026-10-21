# HVMC Azure screenshots and backups

Captured 15 Oct 2026, before the Azure free trial ends on 17 Oct 2026 at 16:01 UTC.

Every image in folders 01-05 shows a read-only Azure CLI or Microsoft Graph command and its real output from the live HVMC
subscription (c3640794...) and Entra ID tenant (174049fa...). `json_exports/` holds the raw configuration for the key items.

| Folder | What's inside |
|---|---|
| 01_subscription_and_cost | Account, free-trial credit and end date, credit used by resource type, $10 budget |
| 02_resources_and_network | Resource inventory, VNet and subnets, rules of all 3 NSGs, Bastion/LB/NAT/public IPs, storage security, ePHI blob protection |
| 03_entra_id | 32 users, 10 SG-* groups with members, directory roles, tenant policies and security defaults, custom role HVMC-Nurse-EHR-ReadOnly, RBAC assignments |
| 04_logging_alerting | Log Analytics workspace, data per table, Activity Log export, VNet flow log, 9 alert rules, alerts fired, network flows |
| 05_defender_sentinel | Defender plans, secure score and recommendations, Defender alerts, Sentinel rules, incidents (all closed), Workbook |
| 06_secops_lab_15oct | All screenshots from the SecOps & IR rubric (incl. Azure portal: workbook, Defender alert, alert e-mail) + HTML dashboard |
| 07_earlier_azure_screenshots | Your own Azure portal screenshots from Sept 2026 (fundamentals, architecture, IAM implementation) |
| 08_arm_template_backup | ARM template export of HVMC-CloudSecurity-RG (938 resource definitions) - can rebuild the environment |

Note: these files show tenant user names, roles and network rules - keep them private (do not push to a public repo).
