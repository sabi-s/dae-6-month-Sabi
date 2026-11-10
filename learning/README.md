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

### ✅ Entry 2 (Task 1)

**📆 Date:** 2026-11-05  
**🛠️ Task:** Created resource group and RBAC-enabled Key Vault; stored first dummy secrets.

**What I built**

| Item | Setting |
|---|---|
| Resource group | `HVMC-KeyVault-RG` (East US), tags `project=HVMC-AccessGuard`, `purpose=learning-keyvault`, `data=dummy-only` |
| Vault | `hvmc-accessguard-kv`, **Standard** tier |
| Permission model | **Azure RBAC** (no legacy access policies) |
| Soft delete / purge protection | On, 7-day retention / **On** (cannot be turned off) |
| My access | **Key Vault Secrets Officer** at the vault scope only |
| Secrets | `servicenow-lab-password`, `accessguard-api-key`: random dummy values, never printed or saved |

**🔍 Evidence:**

-   Branch: `feature/azure-key-vault-setup`
-   Draft PR: _link here_
-   Script: [scripts/task1_create_vault.sh](./scripts/task1_create_vault.sh) (dry run by default, `--apply` to create)
-   Screenshot: [PROOF/01_keyvault_overview.png](./PROOF/01_keyvault_overview.png)
-   Report (PDF): [PROOF/HVMC_KeyVault_Task1_Report.pdf](./PROOF/HVMC_KeyVault_Task1_Report.pdf)
-   Command output:
    ```bash
    $ az keyvault show -n hvmc-accessguard-kv --query "{name:name,sku:properties.sku.name,rbacAuthorization:properties.enableRbacAuthorization,softDelete:properties.enableSoftDelete,retentionDays:properties.softDeleteRetentionInDays,purgeProtection:properties.enablePurgeProtection}" -o table
    Name                 Sku       RbacAuthorization    SoftDelete    RetentionDays    PurgeProtection
    -------------------  --------  -------------------  ------------  ---------------  -----------------
    hvmc-accessguard-kv  standard  True                 True          7                True

    $ az keyvault secret show --vault-name hvmc-accessguard-kv -n servicenow-lab-password   # value masked
    {
      "contentType": "dummy lab value",
      "created": "2026-11-05T17:41:19+00:00",
      "enabled": true,
      "name": "servicenow-lab-password",
      "value": "********  (masked, 32 chars)"
    }

    $ az keyvault secret show --vault-name hvmc-accessguard-kv -n accessguard-api-key       # value masked
    {
      "contentType": "dummy lab value",
      "created": "2026-11-05T17:41:20+00:00",
      "enabled": true,
      "name": "accessguard-api-key",
      "value": "********  (masked, 32 chars)"
    }

    $ az role assignment list --scope <vault-id> --query "[].{role:roleDefinitionName,type:principalType}" -o table
    Role
    -------------------------
    Key Vault Secrets Officer
    ```

**📝 Notes:**

-   Challenges faced and how I solved them:
    -   **No active subscription.** My free trial had ended, and the portal would not create a new subscription until the account was upgraded. Upgrading would have restarted ~$90–130/month of old lab resources. I saved a read-only evidence snapshot first, upgraded with the free Basic support plan, then straight away set a $10/month budget with e-mail alerts, paused the flow log, capped Log Analytics data, and removed only the NAT gateway, load balancer and their public IPs (screenshots already taken). Expected cost now: about $2–5/month.
    -   **Owner is not enough to write secrets.** With the RBAC model, Owner manages the vault (control plane) but cannot read or write secrets (data plane). I gave myself **Key Vault Secrets Officer** on this vault only, not the subscription, and waited about a minute for the role to take effect.
    -   **Keeping secret values out of logs.** The script generates each value in Python, writes it to a temporary file readable only by me, uploads it with `--file` (so it never appears on the command line or in shell history), and deletes the file. Proof output masks the value.
    -   **After the upgrade, Azure stayed read-only for about 8 minutes** (`ReadOnlyDisabledSubscription`) even though the status said Enabled. The script was safe to re-run, so I retried until it worked.
-   Areas to improve or explore further:
    -   Task 2: map the Day 2 RBAC groups to Key Vault Administrator / Reader / Secrets User and prove least privilege (Reader denied secret values).
    -   Task 3: read a secret from Python with `DefaultAzureCredential` and send vault audit logs to Log Analytics.
    -   Network hardening (firewall / private endpoint) is out of scope for this month; public access is used for the lab only.

---

### ✅ Entry 3 (Task 2)

**📆 Date:** 2026-11-09 – 2026-11-10  
**🛠️ Task:** Mapped Day 2 security groups to Key Vault roles and tested least privilege.

**🔍 Evidence:**

-   Deliverable v1.1 (PDF, IDs masked): [PROOF/AccessGuard_Health_KeyVault_Task2_Deliverable.pdf](./PROOF/AccessGuard_Health_KeyVault_Task2_Deliverable.pdf)
-   3 groups at vault scope: SG-IT-KeyVault-Admin (Key Vault Administrator), SG-Security-KeyVault-Read (Key Vault Reader), SG-Services-KeyVault-SecretsUser (Key Vault Secrets User)
-   Test results:
    ```text
    Secrets User (app, certificate sign-in):  read secret = allowed | create = 403 ForbiddenByRbac | delete = 403 ForbiddenByRbac
    Reader (app moved temporarily, option B): list names = allowed  | read value = 403 ForbiddenByRbac | create = 403 ForbiddenByRbac
    ```

**📝 Notes:**

-   Challenges faced and how I solved them:
    -   **Roles add up.** To test the Reader role on its own, the app was moved out of the Secrets User group into the Reader group for the test, then moved back. Every move is in the Entra audit log.
    -   **Certificate sign-in rejected (AADSTS7000215).** Newer Azure CLI needs `--certificate` instead of `-p`.
    -   **The CLI group member list does not show service principals.** Checked membership from the app's side (`memberOf`) and in the audit log before changing anything.
    -   **Wrong identity in a terminal tab.** An old tab was still signed in as the app ("Insufficient privileges"), and a new tab silently used the admin login. Lesson: always confirm who is signed in (`az account show`) before trusting a result.
    -   **Group changes are cached.** After the app was moved back, access was still denied for over 40 minutes although membership and role assignment were correct. The access-restore re-check is pending.
-   Areas to improve or explore further:
    -   Option A (test the Reader role as Denise Coleman, a real user) for a second confirmation.
    -   Task 3: read the secret from Python with `DefaultAzureCredential` and send vault audit logs to Log Analytics.

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
