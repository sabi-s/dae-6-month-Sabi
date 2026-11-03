# learning/PLAN.md

> This is my one-page learning plan for the month. I will complete and commit this file during the 15-minute selection clinic. It records the technology I chose to learn, why I chose it for my capstone, the three focused tasks I will complete, and the proof I will capture to show I did the work.

---

## Student commitment

-   **Name:** Sabitha S Karanavar
-   **Date created:** 2026-11-03

I commit to treat this plan as my personal roadmap: I will keep dates realistic, finish each small task, capture evidence of success, and update this file if anything changes.

---

## Chosen technology

-   **Technology name:** Azure Key Vault (secrets management)
-   **Technology version (if applicable):** Azure Key Vault, Standard tier, Azure RBAC permission model; Azure CLI (`az`) and Python SDKs `azure-identity` and `azure-keyvault-secrets`

### Why I chose this technology

My capstone, AccessGuard Health (Horizon Valley Medical Center IAM simulation), uses credentials such as service account passwords, API keys, and connection strings for the lab. Azure Key Vault will store these in one central, audited place so no secret lives in code, scripts, or documents, and I will control access to it with the same RBAC model and security groups I designed in Week 1. It adds secrets management, least-privilege secret access, and an audit trail, which are core IAM skills for the entry-level cybersecurity roles I am applying to.

**Future consideration:** HashiCorp Vault is not part of this month's scope. I plan to integrate it in a later phase of AccessGuard Health, for example to manage secrets for the on-premises Samba4 domain controller, try dynamic (short-lived) credentials, and compare it with Azure Key Vault in a hybrid design.

---

## First-day actions (complete in the 15-minute selection clinic)

1. Finalize the **Chosen technology** and **Why I chose this technology** fields above.
2. Draft three small integration tasks below with realistic start and target completion dates.
3. Commit this file to the repository at `learning/PLAN.md` before the end of the 15-minute clinic.
4. Record where I will start Task 1 (for example: local branch name or workspace folder) under Task 1.
5. If a task feels too large, I will make it smaller and update the dates here.

---

## My three integration tasks (small, testable, dated)

For each task include Title, Description, Start date, Target completion date, a clear Success criterion, and the Proof method I will capture to show success.

> Dates below are proposed starting from 2026-11-03. Adjust them to match my real deadline.

**Task 1 — Title: Create an RBAC-enabled Key Vault and store the first secrets**

-   **Description:** Create a resource group and an Azure Key Vault with the Azure RBAC permission model, soft delete, and purge protection. Store two dummy lab secrets (for example `servicenow-lab-password` and `accessguard-api-key`).
-   **Start date:** 2026-11-03
-   **Target completion date:** 2026-11-05
-   **Success criterion (explicit):** `az keyvault secret show` returns the stored dummy secret, and `az keyvault show` confirms RBAC authorization and purge protection are enabled.
-   **Proof method (what I will capture to show success):** Terminal output of both commands (secret value masked) pasted into `learning/README.md`, plus a screenshot of the vault Overview page in the Azure portal.
-   **Where I will start Task 1:** local branch `feature/azure-key-vault-setup` in the `dae-6-month-Sabi` repo, folder `learning/`

**Task 2 — Title: Map the Day 2 RBAC model to Key Vault roles and test least privilege**

-   **Description:** Create the security groups `SG-IT-KeyVault-Admin`, `SG-Security-KeyVault-Read`, and `SG-Services-KeyVault-SecretsUser`, and assign them the Key Vault Administrator, Key Vault Reader, and Key Vault Secrets User roles at the vault scope. Test what each identity can and cannot do.
-   **Start date:** 2026-11-06
-   **Target completion date:** 2026-11-10
-   **Success criterion (explicit):** The Key Vault Reader identity can list secret names but is denied (Forbidden) when reading a secret value, and the Secrets User identity can read a secret but cannot create or delete one.
-   **Proof method (what I will capture to show success):** Screenshots of the role assignments and terminal output showing the allowed and denied results, saved in `PROOF/` and linked from `learning/README.md`.

**Task 3 — Title: Replace a hardcoded secret in a Python script and enable audit logging**

-   **Description:** Update one Python script in AccessGuard Health to read its secret from Key Vault with `DefaultAzureCredential` instead of a hardcoded value or `.env` file. Turn on diagnostic logging to a Log Analytics workspace and view the access events.
-   **Start date:** 2026-11-11
-   **Target completion date:** 2026-11-16
-   **Success criterion (explicit):** The script runs with no secret in the code or repository, and a Log Analytics query shows a `SecretGet` event for the script's identity.
-   **Proof method (what I will capture to show success):** Screenshot or output of the passing script run, the Log Analytics query result, and a `git grep` showing no secret in the repo, all linked from `learning/README.md`.

> Note: Keep each task small enough that one task = one focused change or one short demo.

---

## Risks, assumptions, and blockers (one-line each)

-   Requires an Azure subscription (free account or credits) and permission to create resource groups and Key Vaults.
-   Assigning RBAC roles needs Owner or User Access Administrator rights on the scope.
-   Key Vault names must be globally unique (3–24 characters).
-   Role assignments can take a few minutes to take effect.
-   All secret values are dummy or lab-generated; no real credentials, PHI, or PII.
-   Log Analytics ingestion can be delayed by several minutes.

---

## My weekly timeline (one-line plan)

-   **Week 1:** Commit this PLAN, install Azure CLI on my Mac, and complete Task 1; start Task 2.
-   **Week 2:** Finish Task 2; complete Task 3 (script integration and audit logging).
-   **Week 3:** Add tests/logging, finalize PR(s) or demo(s); draft `learning/TUTORIAL.md` and `learning/REFLECTION.md`.
-   **Week 4:** Polish evidence, complete `mock_interview.md`, and note HashiCorp Vault as the next phase.

I will replace the above with exact dates in the tasks section once I finalize them.
