# 🧪 Mock Interview Questions & Answers

This file is a living document of technical and reflective questions based on my Semester 5 self-learning and integration project: adding **Azure Key Vault** to AccessGuard Health, my healthcare IAM simulation.  
Answers marked **[edit]** are drafts: replace them with what actually happened to you before using them in a real interview.

---

## 📌 How to Use This File

-   Read each question out loud and answer it before reading my draft.
-   Replace every **[edit]** and `YYYY-MM-DD` with real details and real evidence.
-   Never include real secret values in screenshots or logs.

---

### What new technology did you learn and why?

I learned **Azure Key Vault**, Microsoft's managed service for storing secrets, keys, and certificates, and integrated it into AccessGuard Health, my Horizon Valley Medical Center IAM simulation.

**Why this tech:**

-   Job-aligned: IAM and security roles expect secrets management, least privilege, and audit trails, and Azure/Entra ID is widely used in healthcare.
-   Project fit: my project already uses Azure (Entra ID) and has scripts that need credentials, so Key Vault connects directly to what I built.
-   Personal gap: I had always seen credentials stored in `.env` files or code and wanted to learn the proper way to manage them.

---

### How did you integrate it into your project?

1. Created a resource group and a Key Vault with the Azure RBAC permission model, soft delete, and purge protection.
2. Stored dummy lab secrets (for example a ServiceNow lab password and an API key).
3. Mapped my Week 1 RBAC design to Key Vault roles: IT Administrators get Key Vault Administrator, Security Officers get Key Vault Reader, and applications get Key Vault Secrets User.
4. Updated a Python script to read its secret with `DefaultAzureCredential` and `SecretClient` instead of a hardcoded value.
5. Turned on diagnostic logging to Log Analytics to see who read which secret.

```python
client = SecretClient(vault_url=os.environ["VAULT_URL"], credential=DefaultAzureCredential())
secret = client.get_secret("servicenow-lab-password")
```

---

### Why did you choose the RBAC permission model instead of access policies?

RBAC uses the same role assignments and Entra ID groups as the rest of Azure, so I can manage Key Vault access the same way I designed access in my RBAC matrix, with groups rather than individual users. It also gives finer separation, such as a role that can see secret metadata but not values. Access policies are the older model and are managed separately from the rest of Azure.

---

### How did you apply least privilege and separation of duties?

-   IT Administrators manage secrets (Key Vault Administrator).
-   Security Officers can review metadata and audit logs but cannot read secret values (Key Vault Reader).
-   Applications can only read the secrets they need (Key Vault Secrets User).
-   Contractors and all other roles have no access.

The people who audit access are different from the people who administer secrets.

---

### What was the most difficult part?

**[edit]** Replace with your real experience. Common issues to compare against:

-   Understanding that being the vault owner does not automatically let you read secrets under RBAC; you need a data-plane role such as Key Vault Secrets Officer.
-   Waiting for role assignments to take effect before a Forbidden error went away.
-   Choosing a vault name that was globally unique.

---

### Show an example of test output or evidence

**[edit]** Paste real output here after completing the tasks.

```bash
# Allowed: Secrets User reads a secret
Secret retrieved: servicenow-lab-password

# Denied: Reader tries to read a secret value
Forbidden: caller does not have secrets get permission
```

Also link: role assignment screenshot, Log Analytics `SecretGet` query result, and the `git grep` check showing no secret in the repo.

---

### How did you verify your integration worked?

-   Ran the script with no secret in the code and confirmed it retrieved the value.
-   Tested the denied path: a Reader identity could list secret names but not read values.
-   Queried the Key Vault audit log for `SecretGet` events to confirm the access was recorded.
-   Ran `git grep` to confirm no secret value was committed.

---

### What tradeoffs or alternatives did you consider?

-   **Environment variables / `.env` files:** simple, but secrets sit on disk or in shell history, with no central control or audit trail.
-   **HashiCorp Vault:** very powerful, with dynamic short-lived credentials and multi-cloud support, but it must be run and secured by me. Azure Key Vault is managed and uses the Entra ID identities I already have.
-   **Azure Key Vault:** chosen because it is managed, ties into Entra ID and Azure RBAC, and fits my project.

---

### Why not HashiCorp Vault now, and when would you use it?

Azure Key Vault fit my current cloud-based Entra ID lab with the least setup. HashiCorp Vault is a **future consideration**: I would add it to manage secrets for on-premises systems such as the Samba4 domain controller on my Ubuntu VM, explore dynamic credentials, and compare it with Azure Key Vault in a hybrid design.

---

### What edge case did you handle or miss?

-   Handled: soft delete and purge protection so deleted secrets can be recovered; never printing or logging secret values.
-   **[edit]** Missed or still to do: secret rotation on a schedule, alerts on repeated Forbidden attempts, and network restrictions (private endpoints or firewall rules) on the vault.

---

### How would you improve this integration?

-   Automate vault creation and role assignment with scripts or infrastructure as code.
-   Rotate secrets on a schedule and when an administrator leaves or changes role.
-   Alert on repeated denied access in Azure Monitor.
-   Add HashiCorp Vault in a later phase for on-premises secrets.

---

_Last updated: 2026-11-03_
