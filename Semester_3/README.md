# Semester 3 — AccessGuard Health (Healthcare IAM Project)

**AccessGuard Health** is a simulated Identity and Access Management (IAM) programme for **Horizon Valley Medical Center (HVMC)**,
a fictional hospital. It covers the full identity lifecycle for doctors, nurses, IT, security and contractors: building the
directory, role-based access, joiner / mover / leaver processes, access reviews, MFA support and secrets management.

**Technology:** Samba Active Directory on Ubuntu (on-premises lab) · Microsoft Entra ID · Microsoft Graph and PowerShell ·
Python · Azure (Key Vault, Log Analytics) · ServiceNow-style tickets.

> All people, accounts and data are fictional. Raw tenant exports, IDs and secrets are kept out of this repository on purpose.

---

## Start here

| If you want to see… | Open |
|---|---|
| The main report of the hands-on IAM work | [HVMC_IAM_Hands_On_Entra_Operations.pdf](./AccessGuard_Health_IAM_Project/02_Entra_ID_Hands_On_Operations/HVMC_IAM_Hands_On_Entra_Operations.pdf) |
| Everything in the project, by week | [AccessGuard_Health_IAM_Project](./AccessGuard_Health_IAM_Project/README.md) |
| The 10 hands-on Entra ID steps (scripts, tickets, results) | [02_Entra_ID_Hands_On_Operations](./AccessGuard_Health_IAM_Project/02_Entra_ID_Hands_On_Operations/README.md) |
| Standard Operating Procedures (create, disable, MFA reset, access review) | [SOPs](./AccessGuard_Health_IAM_Project/02_Entra_ID_Hands_On_Operations/SOPs/) |
| Secrets management with Azure Key Vault | [03_Azure_Key_Vault](./AccessGuard_Health_IAM_Project/03_Azure_Key_Vault/README.md) |
| Weekly and monthly status updates | [Semester3_Status_Update](./Semester3_Status_Update/) |

## Folder structure

```
Semester_3/
├── AccessGuard_Health_IAM_Project/
│   ├── 01_Weekly_Deliverables/          Week-by-week documents (Weeks 1, 2, 5, 7, 8)
│   ├── 02_Entra_ID_Hands_On_Operations/ Main report, SOPs and Steps 01–10 in Microsoft Entra ID
│   └── 03_Azure_Key_Vault/              Link page for the Key Vault learning work
└── Semester3_Status_Update/             Status update decks
```

## About Weeks 3, 4 and 6

There are no separate project documents for Weeks 3, 4 and 6. In those weeks the main focus was the course **rubrics**, while
project work continued in parallel in the Entra ID hands-on steps. The rubric work is in its own folders:

- [Risk management](../risk_management%201/) — risk assessment techniques and evaluation methods
- [Cryptography](../cryptography_1/) — fundamentals, hashing, symmetric and public-key cryptography, digital signatures, protocols
- [Cloud security](../cloud_security_1/) — architecture, implementation, compliance, infrastructure, SecOps and incident response

**Author:** Sabitha S Karanavar
