# 📘 Learning Log

This folder documents my self-learning and integration of **Azure Key Vault** into my existing project, **AccessGuard Health** (Horizon Valley Medical Center IAM simulation).  
It contains my initial plan, daily progress log, and supporting evidence (e.g. test output, branches, and PRs) that demonstrate what I learned and how I applied it.

**Future consideration:** HashiCorp Vault will be integrated in a later phase of the project (see [PLAN.md](./PLAN.md)).

---

## 🔗 Link to Plan

[PLAN.md](./PLAN.md) – My initial plan with chosen technology, rationale, and integration tasks.

Other files in this folder: [NOTES.md](./NOTES.md) (observability notes), [TUTORIAL.md](./TUTORIAL.md) (mini-tutorial), [mock_interview.md](./mock_interview.md) (interview prep).

---

## 📅 Daily Progress Log

_Add one dated entry each time you make progress. Include short notes, outputs, and links to branches or pull requests. Use fenced code blocks (` ``` `) for logs or commands._

### ✅ Entry 1

**📆 Date:** 2026-11-03  
**🛠️ Task:** Chose Azure Key Vault and wrote the learning plan.

**🔍 Evidence:**

-   Branch: `feature/azure-key-vault-setup`
-   File: [PLAN.md](./PLAN.md)

**📝 Notes:**

-   Chose Azure Key Vault to store the lab's secrets (service account passwords, API keys, connection strings) outside of code.
-   Decided to use the Azure RBAC permission model so Key Vault access follows the same group-based design as my Week 1 RBAC matrix.
-   Recorded HashiCorp Vault as a future consideration, not part of this month's scope.

---

### Entry 2 (Task 1) — fill in after completing

**📆 Date:** YYYY-MM-DD  
**🛠️ Task:** Created resource group and RBAC-enabled Key Vault; stored first dummy secrets.

**🔍 Evidence:**

-   Branch: `feature/azure-key-vault-setup`
-   Draft PR: _link here_
-   Command output:
    ```bash
    az keyvault show --name <vault-name> --query "{rbac:properties.enableRbacAuthorization, purgeProtection:properties.enablePurgeProtection}"
    # paste real output here (do not paste secret values)
    ```

**📝 Notes:**

-   Challenges faced and how I solved them:
-   Areas to improve or explore further:

---

### Entry 3 (Task 2) — fill in after completing

**📆 Date:** YYYY-MM-DD  
**🛠️ Task:** Mapped Day 2 security groups to Key Vault roles and tested least privilege.

**🔍 Evidence:**

-   Screenshots: `PROOF/role-assignments.png`, `PROOF/reader-forbidden.png`
-   Test Output:
    ```bash
    # paste real allowed/denied output here
    ```

**📝 Notes:**

-   Challenges faced and how I solved them:
-   Areas to improve or explore further:

---

### Entry 4 (Task 3) — fill in after completing

**📆 Date:** YYYY-MM-DD  
**🛠️ Task:** Replaced a hardcoded secret in a Python script with a Key Vault lookup and enabled audit logging.

**🔍 Evidence:**

-   Branch: `feature/keyvault-python-integration`
-   Draft PR: _link here_
-   Test Output:
    ```bash
    # paste real script run and Log Analytics SecretGet result here
    ```

**📝 Notes:**

-   Challenges faced and how I solved them:
-   Areas to improve or explore further:

---

## 🧱 Entry Template (copy and update each time)

**📆 Date:** YYYY-MM-DD  
**🛠️ Task:** _What did you do?_

**🔍 Evidence:**

-   Branch: `feature/...`
-   Draft PR: _link here_
-   Test Output:  
    \```bash  
    _Insert console output or command log_  
    \```

**📝 Notes:**

-   Mention any challenges faced and how you solved them.
-   Note areas you want to improve or explore further.

---

## 📌 Tips for Maintaining This Log

-   Keep adding entries as you progress day by day.
-   Include real commands, outputs, screenshots (if supported), and links.
-   Never paste real secret values or keys into this log; mask them.
-   Keep answers specific enough that you can explain them in a mock interview.
