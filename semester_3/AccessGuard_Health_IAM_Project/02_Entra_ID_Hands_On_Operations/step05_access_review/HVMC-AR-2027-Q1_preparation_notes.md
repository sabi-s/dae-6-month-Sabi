# HVMC Access Review HVMC-AR-2027-Q1 — preparation notes

Items noted between reviews, to be checked in the next quarterly access review (due January 2027).
Previous review: HVMC-AR-2026-Q4 (20 Oct 2026, 94 lines, 1 removal).

## N1 — Service accounts and workload identities (noted 29 Oct 2026)

Read-only inventory of the Entra ID tenant (Microsoft Graph, no changes):

| Category | Count | Detail | Assessment |
|---|---|---|---|
| User accounts used by programs (classic "service accounts") | 0 | No account named or titled svc / service / sync / api / bot | Good — matches Microsoft guidance to use workload identities instead |
| Accounts without an employee ID | 4 | IAM administrator; Emergency Access 01 and 02 (break glass, created 28 Oct, HVMC-IAM-CHG-107); Test Nurse - EHR (disabled since HVMC-IAM-CHG-101) | All expected; confirm the test account is still disabled and still has no roles |
| HVMC application service principals | 11 | 10 "HVMC ..." apps (HVMC-IAM-CHG-103) + legacy EHR-Simulated | No secrets, no certificates, no API permissions — cannot authenticate on their own |
| Managed identities | 2 | StorageDataScanner; StorageAccounts/securityOperators/DefenderForStorageSecurityOperator | Created by Microsoft Defender for Storage during the Cloud SecOps lab (15 Oct 2026) |
| Microsoft / third-party service principals | 123 | Microsoft first-party apps present in every tenant | No action |

**Finding to review:** the two Defender for Storage managed identities are probably **orphaned** — the Azure
subscription has been disabled since 17 Oct 2026 (free trial ended). They hold no secrets and cannot be used while
the subscription is disabled.
**Proposed decision:** keep for now (platform-managed). If the subscription is re-activated for the Azure Key Vault
work, confirm whether Defender for Storage is still wanted; if the subscription is deleted, confirm the identities were
removed automatically.

**On-premises (hvmc.lan):** the "Service Accounts" OU on hvmc-dc01 is empty. If a service account is needed there,
prefer a group Managed Service Account (gMSA) where supported, otherwise a dedicated account with a long random
password, no interactive logon, and an owner recorded in the review.

## Also check in HVMC-AR-2027-Q1
- Break-glass accounts: quarterly sign-in test done (due ~28 Jan 2027); still exactly two; no use outside emergencies.
- Global Administrators: exactly three (IAM administrator + two break-glass).
- Contractor accounts: Carlos Diaz (HVMC-JML-203) still disabled with no groups or app assignments.
