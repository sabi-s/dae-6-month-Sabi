# 🔭 Next Phase: HashiCorp Vault

**Status:** future consideration — **not** part of this month's scope ([PLAN.md](./PLAN.md)). Azure Key Vault is in place and tested.

## Why a next phase

AccessGuard Health has two halves: the **cloud** side (Microsoft Entra ID, Azure) and the **on-premises** side (the Samba
Active Directory domain controller on Ubuntu). Azure Key Vault now protects the cloud side. HashiCorp Vault is a good fit for
the on-premises and hybrid side.

## What I would try

| Idea | Why it matters for HVMC |
|---|---|
| Run Vault on the lab Ubuntu server (dev mode first, then with TLS and a storage backend) | Learn how a self-managed secrets service is installed, sealed / unsealed and secured |
| **Dynamic secrets** — short-lived database or LDAP credentials created on request | No standing passwords: a credential exists only for the minutes it is needed |
| LDAP secrets engine against the Samba AD domain controller | Automatic rotation of service-account passwords on the on-premises domain |
| AppRole / certificate authentication for the HVMC Lab Results Sync job | Same "application, not person" pattern as in Azure |
| Audit device to a log file / SIEM | Compare its audit trail with Key Vault's `SecretGet` logs |
| Side-by-side comparison with Azure Key Vault | Decide which system fits which workload in a hybrid design |

## Azure Key Vault vs HashiCorp Vault (my current understanding)

| | Azure Key Vault | HashiCorp Vault |
|---|---|---|
| Hosting | Managed by Microsoft | I run and secure it (or HCP Vault, managed) |
| Identity | Entra ID + Azure RBAC | Many auth methods (AppRole, LDAP, certificates, cloud identities) |
| Best at | Static secrets, keys and certificates for Azure workloads | Dynamic, short-lived secrets; multi-cloud and on-premises |
| Effort for my lab | Low — already integrated | Higher — install, unseal, policies, backups |

## Success criteria for the next phase (draft)

-   A script reads a secret from HashiCorp Vault with no secret in the code (same test as Task 3).
-   A dynamic credential is issued, used and automatically revoked.
-   The audit log shows each read.
