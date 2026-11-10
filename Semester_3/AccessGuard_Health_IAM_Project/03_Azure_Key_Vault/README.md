# Azure Key Vault — Secrets Management

AccessGuard Health's lab secrets (service passwords, API keys) are moved out of scripts and `.env` files into **Azure Key Vault**,
with access controlled by Entra ID groups and Azure RBAC roles.

This work follows the course learning-plan template, so it lives in the [`learning/`](https://github.com/sabi-s/dae-6-month-Sabi/tree/feature/azure-key-vault-setup/learning)
folder on the branch **`feature/azure-key-vault-setup`**.

| Task | What | Status | Evidence |
|---|---|---|---|
| 1 | RBAC-enabled vault with soft delete and purge protection; first dummy secrets | ✅ Done (5 Nov 2026) | [Task 1 report](https://github.com/sabi-s/dae-6-month-Sabi/blob/feature/azure-key-vault-setup/learning/PROOF/HVMC_KeyVault_Task1_Report.pdf) |
| 2 | Map the Day 2 RBAC model to Key Vault roles; test least privilege (Reader denied secret values, Secrets User cannot create or delete) | ✅ Done (10 Nov 2026) | [Task 2 deliverable](https://github.com/sabi-s/dae-6-month-Sabi/blob/feature/azure-key-vault-setup/learning/PROOF/AccessGuard_Health_KeyVault_Task2_Deliverable.pdf) |
| 3 | Python script reads a secret with `DefaultAzureCredential` (no secret in code); vault audit logs in Log Analytics | ✅ Done (10 Nov 2026) | [Task 3 report](https://github.com/sabi-s/dae-6-month-Sabi/blob/feature/azure-key-vault-setup/learning/PROOF/HVMC_KeyVault_Task3_Report.pdf) |

Plan and daily log: [PLAN.md](https://github.com/sabi-s/dae-6-month-Sabi/blob/feature/azure-key-vault-setup/learning/PLAN.md) ·
[README.md](https://github.com/sabi-s/dae-6-month-Sabi/blob/feature/azure-key-vault-setup/learning/README.md)
