# Cloud Security — HVMC on Microsoft Azure

Six cloud security rubrics, all applied to Horizon Valley Medical Center's Azure environment.

| Rubric | Folder | Main document |
|---|---|---|
| Cloud security fundamentals | [01_cloud_security_fundamentals](./01_cloud_security_fundamentals/) | Cloud Security Fundamentals (Azure) |
| Cloud IAM implementation | [02_cloud_iam_implementation](./02_cloud_iam_implementation/) | IAM Implementation Documentation |
| Cloud architecture design and security patterns | [03_cloud_architecture_security_patterns](./03_cloud_architecture_security_patterns/) | AccessGuard Health cloud architecture and security patterns, patient-portal architecture, HIPAA checklist |
| Cloud compliance and governance controls | [04_cloud_compliance_governance_controls](./04_cloud_compliance_governance_controls/) | HVMC Cloud Compliance and Governance Controls **v2.0** – **live Azure lab:** Azure Policy guardrails (Deny), mandatory-tag initiative, delete locks on logging, HITRUST/HIPAA compliance scan and enforcement tests ([04_azure_governance_lab](./04_cloud_compliance_governance_controls/azure_governance_lab/)) |
| Cloud infrastructure security and container protection | [05_cloud_infrastructure_security_container_protection](./05_cloud_infrastructure_security_container_protection/) | VM hardening scripts, hardened Dockerfile with image scanning, serverless Function with managed identity (Bicep). The report uses **simulated** results — nothing was deployed. |
| Cloud SecOps and incident response | [06_cloud_secops_incident_response](./06_cloud_secops_incident_response/) | **Live Azure lab:** Log Analytics, activity-log alerts, Defender for Cloud, Microsoft Sentinel with custom rules, workbook, incident-response playbook and tests; [06_Defender for Cloud video walkthrough](./06_cloud_secops_incident_response/video/) |

Other files: [all_screenshots](./all_screenshots/) (evidence by topic).
