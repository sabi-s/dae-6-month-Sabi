# 📘 Mini-Tutorial: Storing and Reading Secrets with Azure Key Vault (RBAC) on a Mac

_A student-authored tutorial documenting a key integration learned in Semester 5._

---

## ❓ What This Teaches

This tutorial shows how to create an Azure Key Vault that uses Azure role-based access control (RBAC), store a secret in it, and read that secret from a Python script without ever putting the secret in code. It solves the problem of hardcoded passwords and API keys in scripts and config files. Any project that uses credentials, such as my AccessGuard Health IAM simulation, benefits from it.

> All secret values in this tutorial are dummy lab values. Never store real credentials in a practice vault.

---

## 🎯 Use Case

> A healthcare IAM lab needs service account passwords and API keys available to scripts, but only to the right identities, with an audit trail.

-   [ ] Backend development
-   [x] Cybersecurity
-   [x] Monitoring / Observability
-   [ ] Performance / Testing
-   [x] Authentication / Authorization
-   [ ] DevOps / Deployments
-   [ ] Other: _Secrets management / IAM_

---

## 🚀 Quick Setup / Install

Tools needed: Homebrew, Azure CLI, Python 3.

```bash
brew install azure-cli
az login
pip install azure-identity azure-keyvault-secrets
```

---

## 🛠️ Step-by-Step Guide

1. **Create a resource group and a vault with RBAC and purge protection:**

    ```bash
    az group create --name rg-accessguard --location eastus

    az keyvault create \
      --name kv-accessguard-<unique> \
      --resource-group rg-accessguard \
      --location eastus \
      --enable-rbac-authorization true \
      --enable-purge-protection true
    ```

    Vault names must be globally unique (3–24 characters). Soft delete is on by default.

2. **Give yourself permission to manage secrets** (RBAC means being the owner is not enough to read or write secrets):

    ```bash
    VAULT_ID=$(az keyvault show --name kv-accessguard-<unique> --query id -o tsv)
    ME=$(az ad signed-in-user show --query id -o tsv)

    az role assignment create \
      --role "Key Vault Secrets Officer" \
      --assignee-object-id $ME \
      --assignee-principal-type User \
      --scope $VAULT_ID
    ```

    Role assignments can take a few minutes to take effect.

3. **Store a dummy secret:**

    ```bash
    az keyvault secret set \
      --vault-name kv-accessguard-<unique> \
      --name servicenow-lab-password \
      --value "dummy-lab-value"
    ```

4. **Read it from Python with no secret in the code:**

    ```python
    import os
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient

    vault_url = os.environ["VAULT_URL"]  # https://kv-accessguard-<unique>.vault.azure.net
    client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())

    secret = client.get_secret("servicenow-lab-password")
    print("Secret retrieved:", secret.name)  # never print the value
    ```

    ```bash
    export VAULT_URL="https://kv-accessguard-<unique>.vault.azure.net"
    python get_secret.py
    ```

5. **Apply least privilege.** Give applications only the Key Vault Secrets User role, and give auditors only Key Vault Reader:

    ```bash
    az role assignment create \
      --role "Key Vault Secrets User" \
      --assignee-object-id <app-identity-object-id> \
      --assignee-principal-type ServicePrincipal \
      --scope $VAULT_ID
    ```

6. **Turn on audit logging** by adding a diagnostic setting on the vault that sends the `AuditEvent` category to a Log Analytics workspace (Azure portal: vault → Diagnostic settings).

---

## ✅ What You Should See

> -   Step 3 returns JSON that includes the secret name and its id.
> -   Step 4 prints `Secret retrieved: servicenow-lab-password`.
> -   An identity with only Key Vault Reader can list secret names but gets a Forbidden error when reading a value.

Embed my own screenshots once captured:

```markdown
![Secret retrieved](../PROOF/secret-retrieved.png)
![Reader denied](../PROOF/reader-forbidden.png)
```

---

## 💡 Pro Tips / Edge Cases

-   Seeing `Forbidden` or `does not have secrets get permission` usually means the RBAC role is missing or has not propagated yet; wait a few minutes and retry.
-   Never print, log, or commit secret values. Check with `git grep` before every push.
-   Purge protection cannot be turned off once enabled, so only use it on vaults you are happy to keep for the retention period.
-   **Future consideration:** HashiCorp Vault could later manage secrets for on-premises systems (such as my Samba4 domain controller) and provide dynamic, short-lived credentials. Azure Key Vault is the right fit for now because it is managed and uses the same Entra ID identities as the rest of my lab.

---

## 📚 Learn More

Link to any docs or references you found useful:

-   [Azure Key Vault documentation](https://learn.microsoft.com/azure/key-vault/)
-   [Provide access to Key Vault with Azure RBAC](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)
-   [azure-keyvault-secrets for Python](https://learn.microsoft.com/python/api/overview/azure/keyvault-secrets-readme)
-   [HashiCorp Vault](https://developer.hashicorp.com/vault) (future consideration)

---

## 👤 Authored by: Sabitha S Karanavar

🗓️ Date: 2026-11-03  
🔁 Validated by: [Educator or Peer Name if applicable]
