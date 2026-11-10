# Entra ID Hands-On IAM Operations

Hands-on IAM work for AccessGuard Health in a Microsoft Entra ID tenant (Entra ID Free, $0). Every change was run as a
**dry run first**, applied only after review, and recorded with a change or ticket number.

**Main report:** [HVMC_IAM_Hands_On_Entra_Operations.pdf](./HVMC_IAM_Hands_On_Entra_Operations.pdf) — all steps, findings and evidence in one document.
**SOPs:** [SOPs/](./SOPs/) — one-page procedures: create account, disable account, reset MFA, run an access review.

## Steps

| Step | Folder | What it does | Change / ticket |
|---|---|---|---|
| 01 | [step01_identity_hygiene](./step01_identity_hygiene/) | Cleans identity data: departments, job titles, managers, employee IDs | HVMC-IAM-CHG-101 |
| 02 | [step02_rbac_v2](./step02_rbac_v2/) | Role-based access groups (SG-&lt;Dept&gt;-&lt;App&gt;-&lt;Access&gt;) matched to the RBAC matrix | HVMC-IAM-CHG-102 |
| 03 | [step03_enterprise_apps](./step03_enterprise_apps/) | 10 hospital applications with app roles; access assigned from the groups | HVMC-IAM-CHG-103 |
| 04 | [step04_jml](./step04_jml/) | Joiner, mover and leaver processes | JML-201 – JML-203 |
| 05 | [step05_access_review](./step05_access_review/) | Quarterly access review: review pack, decisions, removals | HVMC-AR-2026-Q4 |
| 05b | [step05b_second_review_and_matrix](./step05b_second_review_and_matrix/) | Second access review (compared with Q4: 0 new findings) and User Access Matrix v2 (32/32 accounts match) | HVMC-AR-2026-Q4-R2 |
| 06 | [step06_conditional_access](./step06_conditional_access/) | Conditional Access design: 13 report-only policies and a test plan (needs Entra P1/P2 to deploy) | Design only |
| 07 | [step07_tenant_hardening](./step07_tenant_hardening/) | Tenant hardening (user consent, app registration, guest settings) and two break-glass admin accounts | HVMC-IAM-CHG-106 / 107 |
| 08 | [step08_nonhuman_identities](./step08_nonhuman_identities/) | Non-human identity *HVMC Lab Results Sync*: certificate credential, least-privilege permission | HVMC-IAM-CHG-108 |
| 08b | [step08b_lifecycle_automation](./step08b_lifecycle_automation/) | PowerShell lifecycle automation from an HR feed, with a daily leaver check | JML-204 – JML-206, CHG-110 |
| 09 | [step09_credential_cleanup](./step09_credential_cleanup/) | Credential clean-up: reset of the lab accounts' initial passwords | HVMC-IAM-CHG-109 |
| 10 | [step10_mfa_support](./step10_mfa_support/) | MFA support for a lost phone, done by a least-privileged help-desk account | IAM-0004 |

## Notes

- `_tooling/` holds the scripts that build the report PDFs and their shared style.
- Raw tenant exports (`evidence/`), tenant IDs and any `SECRET_*` files are excluded by `.gitignore`. The reports summarise them.
- The scripts were run from a local working folder that uses the original step names (`step1_…`, `step10_…`).
  The folders here were renamed to `step01_…` only so that they sort in order.
