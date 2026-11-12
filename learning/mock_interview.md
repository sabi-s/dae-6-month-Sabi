# 🧪 Mock Interview Questions & Answers

A living document of technical and reflective questions about my Semester 5 self-learning project: adding **Azure Key Vault**
to AccessGuard Health, my Horizon Valley Medical Center (HVMC) IAM simulation. All answers describe what I actually did
(3–10 November 2026); evidence is linked at the end.

---

## 📌 How to Use This File

-   Read each question out loud and answer it before reading my answer.
-   Keep answers short: situation → what I did → result.
-   Never show real secret values in screenshots or logs.

---

### 30-second summary

"In AccessGuard Health I secured application secrets with Azure Key Vault. I built an RBAC-enabled vault with purge protection,
mapped my role-based access model to it with three security groups — Administrator, Reader and Secrets User — scoped to that one
vault, and **proved least privilege with tests**: the Reader could list secret names but got 403 Forbidden on values, and a
certificate-authenticated application could read its secret but not create or delete one. Then I removed a hardcoded API key from
a Python script using `DefaultAzureCredential`, and every read now shows up as `SecretGet` in Log Analytics."

---

### What new technology did you learn and why?

**Azure Key Vault**, Microsoft's managed service for secrets, keys and certificates.

-   **Job-aligned:** IAM and security roles expect secrets management, least privilege and audit trails; Azure and Entra ID are common in healthcare.
-   **Project fit:** my project already used Entra ID and Azure, and my lab scripts needed credentials.
-   **Personal gap:** I had only seen credentials kept in code or `.env` files and wanted to learn the proper way.

---

### How did you integrate it into your project?

1.  **Task 1:** created `hvmc-accessguard-kv` (Standard, Azure RBAC, soft delete 7 days, purge protection) and two dummy secrets, uploaded from a private temp file so the values never appeared on screen.
2.  **Task 2:** created `SG-IT-KeyVault-Admin`, `SG-Security-KeyVault-Read` and `SG-Services-KeyVault-SecretsUser`, each with one built-in role at **vault scope**; added Kevin (IT), Denise (Security) and the app *HVMC Lab Results Sync* (service principal).
3.  **Task 3:** `lab_results_sync.py` reads `accessguard-api-key` at run time:

```python
client = SecretClient(vault_url=VAULT_URL, credential=DefaultAzureCredential())
secret = client.get_secret("accessguard-api-key")   # held in memory only, never printed
```

4.  Turned on the vault's diagnostic setting (`AuditEvent` → Log Analytics) and queried `SecretGet` events.

---

### Why the RBAC permission model instead of access policies?

RBAC uses the same role assignments and Entra ID groups as the rest of Azure, so Key Vault access follows my group design and the
joiner / mover / leaver process. It supports scopes (vault or even a single secret) and gives roles like Reader that see metadata
but not values. Access policies are the older, separate model.

---

### How did you apply least privilege and separation of duties?

-   IT manages the vault's contents (Key Vault Administrator) — scoped to this vault only.
-   Security can audit secret **names** but not read **values** (Key Vault Reader).
-   The application can only read secret values (Key Vault Secrets User) — it cannot create or delete.
-   Everyone else has no access. Auditors are not the people who administer secrets.

---

### What was the most difficult part?

Proving the Reader role. Roles are additive, so I temporarily moved the application **out** of the Secrets User group and **into**
the Reader group — otherwise it could still read values and the test would prove nothing. Then three things surprised me:

-   the Azure CLI's group member list does not show service principals, so the group looked empty — I verified from the app's side and the audit log instead;
-   an old terminal tab was still signed in as the app, and a new tab silently used my admin login — now I always run `az account show` first;
-   after moving the app back, access stayed denied for almost **two hours** because Azure caches service-principal group memberships. Membership and role were correct; I waited and re-tested until it passed.

---

### Show an example of test output or evidence

```text
# Reader (app moved to SG-Security-KeyVault-Read)
$ az keyvault secret list --vault-name hvmc-accessguard-kv --query "[].name" -o tsv
accessguard-api-key
rbac-test-secret
servicenow-lab-password
$ az keyvault secret show --vault-name hvmc-accessguard-kv -n rbac-test-secret --query value -o tsv
(Forbidden) Caller is not authorized to perform action on resource.
Action: 'Microsoft.KeyVault/vaults/secrets/getSecret/action'   Assignment: (not found)   ForbiddenByRbac

# Task 3 script
identity source : AzureCliCredential
secret found    : yes, 32 characters
RESULT : OK - no secret stored in this script or its folder

# Log Analytics
SecretGet  accessguard-api-key  user  lab_results_sync.py (Azure SDK)  OK  200
```

---

### How did you verify your integration worked?

-   **Allowed paths:** Secrets User read a secret; the Reader listed names; the script retrieved its key.
-   **Denied paths:** Reader → read value and create = 403 `ForbiddenByRbac`; Secrets User → create and delete = 403.
-   **Restore:** after the test, the app read its secret again (design restored).
-   **Audit:** a KQL query showed the script's `SecretGet` (and my own admin check — every read is logged).
-   **No secret in Git:** a script reads each real value into memory and searches every file and commit: 0 matches.

---

### How does `DefaultAzureCredential` work, and why use it?

It tries a fixed list of credential types and uses the first that works: environment variables (e.g. an app certificate),
managed identity, Azure CLI login, and others. On my Mac it used my `az login`; on an Azure VM or Function it would use a managed
identity — **same code, no secret anywhere**.

---

### What tradeoffs or alternatives did you consider?

-   **Environment variables / `.env`:** simple, but secrets sit on disk or in shell history, with no central control or audit.
-   **HashiCorp Vault:** powerful (dynamic short-lived credentials, multi-cloud, on-premises) but I would have to run and secure it.
-   **Azure Key Vault:** chosen — managed, uses the Entra ID identities and Azure RBAC I already had, built-in audit logs.

---

### Why not HashiCorp Vault now, and when would you use it?

Key Vault fit my cloud side with the least setup. HashiCorp Vault is my **next phase** for the on-premises side: rotating
service-account passwords on the Samba AD domain controller, dynamic credentials, and a comparison in a hybrid design
([HASHICORP_VAULT_NEXT_PHASE.md](./HASHICORP_VAULT_NEXT_PHASE.md)).

---

### What edge cases did you handle or miss?

-   **Handled:** soft delete and purge protection; values never printed, logged or committed; destructive tests on a throwaway secret; temporary certificate files deleted after each test; screenshots masked before publishing.
-   **Learned:** a new diagnostic setting did not log reads in its first ~20 minutes, and the first events took over 30 minutes to appear.
-   **Still to do:** secret rotation and expiry, alerts on unusual or denied access, network restrictions (private endpoint / firewall).

---

### How would you improve this integration?

-   Run the script as the application or with a **managed identity**, not a person's login.
-   Alert on unusual `SecretGet` activity and repeated `Forbidden` results.
-   Automate vault, groups and role assignments as infrastructure as code.
-   Add HashiCorp Vault in the next phase.

---

### Evidence

[Task 1 report](./PROOF/HVMC_KeyVault_Task1_Report.pdf) · [Task 2 deliverable](./PROOF/AccessGuard_Health_KeyVault_Task2_Deliverable.pdf) ·
[Task 3 report](./PROOF/HVMC_KeyVault_Task3_Report.pdf) · [Daily log](./README.md) · [Reflection](./REFLECTION.md)

---

_Last updated: 2026-11-10_
