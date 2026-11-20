# Azure Governance Lab (20 Nov 2026)

Live implementation behind **Cloud Compliance & Governance Controls v2.0**. Everything here was run against
the HVMC Azure subscription with the Azure CLI. Azure Policy, tags and resource locks are free, so the lab cost $0.

| Step | Script | What it does | Evidence |
|---|---|---|---|
| 0 | [00_baseline.sh](./00_baseline.sh) | Records the state before any change (read-only) | [00_baseline.txt](./evidence/00_baseline.txt) |
| 1 | [01_tag_resource_groups.sh](./01_tag_resource_groups.sh) | Adds the mandatory tag set to the resource groups | [01_tag_resource_groups.txt](./evidence/01_tag_resource_groups.txt) |
| 2 | [02_assign_policies.sh](./02_assign_policies.sh) | Creates the two HVMC initiatives and assigns them, plus the built-in HITRUST/HIPAA initiative (audit only) | [02_assign_policies.txt](./evidence/02_assign_policies.txt) |
| 3 | [03_protect_logging.sh](./03_protect_logging.sh) | CanNotDelete locks on the Sentinel workspace and the security-log storage account | [03_protect_logging.txt](./evidence/03_protect_logging.txt) |
| 4 | [04_enforcement_tests.sh](./04_enforcement_tests.sh) | Requests that break a rule, to prove they are denied | [04_enforcement_tests.txt](./evidence/04_enforcement_tests.txt), [04b_test5_followup.txt](./evidence/04b_test5_followup.txt) |
| 5 | [05_remediate_and_scan.sh](./05_remediate_and_scan.sh) | Remediation tasks that tag existing resources, and a compliance scan | [05_remediate_and_scan.txt](./evidence/05_remediate_and_scan.txt) |
| 5b | [05b_backfill_tags.sh](./05b_backfill_tags.sh) | One-time backfill: all tags in one request per resource (the Step 5 tasks were refused by the Deny rules, see [05_remediation_failures.txt](./evidence/05_remediation_failures.txt)) | [05b_backfill_tags.txt](./evidence/05b_backfill_tags.txt) |
| 6 | [06_compliance_evidence.sh](./06_compliance_evidence.sh) | Collects compliance results and policy deny events after the scan (read-only) | [06_compliance_results.txt](./evidence/06_compliance_results.txt), [06_hipaa_summary.json](./evidence/06_hipaa_summary.json) |
| 7 | [07_summarize_compliance.py](./07_summarize_compliance.py) | Summarises the latest compliance states for the report | [07_compliance_summary.json](./evidence/07_compliance_summary.json) |

The report is built by [_report/build_report.py](./_report/build_report.py) from these evidence files.

## Results (20 Nov 2026)

- Mandatory tags: 0 of 22 resources before, 22 of 22 after
- 4 of 4 policy-violating requests denied; 87 policy deny events in the activity log
- HITRUST/HIPAA: 494 of 510 control groups with no non-compliant resource; 9 findings open (see report section 4.2)

Policy initiative definitions: [policy/](./policy/).

## AWS → Azure mapping

The rubric names AWS services. This lab builds the equivalent controls in Azure, where HVMC actually runs:

| Rubric (AWS) | Built here (Azure) |
|---|---|
| AWS Organizations / OUs | Subscription and resource-group scopes (management groups need tenant-root access) |
| Service Control Policies | Azure Policy initiative **HVMC-Guardrails** with Deny effects |
| Mandatory resource tagging | Initiative **HVMC-Mandatory-Tags** (Modify: inherit from RG, Deny: require tag) |
| AWS Config Rules | Azure Policy compliance evaluation with the built-in **HITRUST/HIPAA** initiative |
| SCP "deny disable logging" | CanNotDelete resource locks on the logging resources |

## Notes

- `mask.sh` replaces the subscription ID, tenant ID and admin e-mail before any output is saved.
- Test 5 (TLS 1.0) was allowed: Azure retired TLS 1.0/1.1 on 2026-02-03 and the CLI upgraded the request
  to TLS 1.2. The empty test account was checked and deleted; see `04b_test5_followup.txt`.
- To undo the lab: delete the policy assignments `hvmc-guardrails`, `hvmc-tags-*` and `hvmc-hipaa-hitrust`,
  and the two locks. Tags can stay.
