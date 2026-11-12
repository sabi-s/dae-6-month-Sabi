# 📘 Mini-Tutorial: Storing and Reading Secrets with Azure Key Vault (RBAC) on a Mac

_A student-authored tutorial documenting a key integration learned in Semester 5._

---

## ❓ What This Teaches

How to create an Azure Key Vault that uses **Azure role-based access control (RBAC)**, give people and applications only the
access they need, read a secret from a Python script **without the secret ever being in the code**, and see every read in an
audit log. It solves the problem of hardcoded passwords and API keys in scripts and `.env` files. I used it in AccessGuard Health,
my Horizon Valley Medical Center (HVMC) IAM simulation.

> All secret values in this tutorial are dummy lab values. Never store real credentials in a practice vault.

---

## 🎯 Use Case

> A healthcare IAM lab needs API keys and service passwords available to scripts, but only to the right identities, with an audit trail.

-   [ ] Backend development
-   [x] Cybersecurity
-   [x] Monitoring / Observability
-   [ ] Performance / Testing
-   [x] Authentication / Authorization
-   [ ] DevOps / Deployments
-   [x] Other: _Secrets management / IAM_

---

## 🚀 Quick Setup / Install

Tools needed: Azure CLI, Python 3, an Azure subscription and a Log Analytics workspace (optional, for step 6).

```bash
brew install azure-cli            # or install it in a Python virtual environment
az login
python3 -m venv .venv
.venv/bin/pip install azure-identity azure-keyvault-secrets
```

**Cost:** the Standard tier has no monthly fee (about $0.03 per 10,000 operations). Audit logs for a lab are a few KB.

---

## 🛠️ Step-by-Step Guide

1. **Create a resource group and a vault with RBAC, soft delete and purge protection**

    ```bash
    az group create --name HVMC-KeyVault-RG --location eastus
    az keyvault create --name hvmc-accessguard-kv --resource-group HVMC-KeyVault-RG --location eastus \
      --sku standard --enable-rbac-authorization true --retention-days 7 --enable-purge-protection true
    ```

    Vault names are globally unique (3–24 characters). Purge protection **cannot be turned off** once enabled.

2. **Give yourself a data-plane role on the vault only.** Being Owner of the subscription manages the vault (control plane)
   but does **not** let you read or write secrets (data plane).

    ```bash
    VAULT_ID=$(az keyvault show --name hvmc-accessguard-kv --query id -o tsv)
    ME=$(az ad signed-in-user show --query id -o tsv)
    az role assignment create --role "Key Vault Secrets Officer" \
      --assignee-object-id "$ME" --assignee-principal-type User --scope "$VAULT_ID"
    ```

3. **Store a secret without it appearing on screen or in shell history** (generate it into a private temp file, upload with `--file`):

    ```bash
    tmp=$(mktemp); chmod 600 "$tmp"
    python3 -c "import secrets,sys; sys.stdout.write(secrets.token_urlsafe(24))" > "$tmp"
    az keyvault secret set --vault-name hvmc-accessguard-kv -n accessguard-api-key --file "$tmp" --query id -o tsv
    rm -f "$tmp"
    ```

4. **Apply least privilege with groups** (one group per job, one role per group, all at vault scope):

    | Group | Role | Can | Cannot |
    |---|---|---|---|
    | SG-IT-KeyVault-Admin | Key Vault Administrator | manage the vault's contents | act outside this vault |
    | SG-Security-KeyVault-Read | Key Vault Reader | see secret **names** (audits) | read secret **values** |
    | SG-Services-KeyVault-SecretsUser | Key Vault Secrets User | read a secret value | create or delete secrets |

    ```bash
    G=$(az ad group show --group SG-Security-KeyVault-Read --query id -o tsv)
    az role assignment create --role "Key Vault Reader" \
      --assignee-object-id "$G" --assignee-principal-type Group --scope "$VAULT_ID"
    ```

5. **Read the secret from Python — no secret in the code** (`DefaultAzureCredential` uses your `az login` on a laptop,
   a managed identity or certificate in production):

    ```python
    import os
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient

    vault_url = os.environ.get("KEY_VAULT_URL", "https://hvmc-accessguard-kv.vault.azure.net")
    client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
    secret = client.get_secret("accessguard-api-key")
    print("secret found:", secret.name, len(secret.value), "characters")   # never print the value
    ```

6. **Turn on audit logging** (category `AuditEvent` → Log Analytics) and query who read which secret:

    ```bash
    LAW=$(az monitor log-analytics workspace show -g <rg> -n <workspace> --query id -o tsv)
    az monitor diagnostic-settings create --name kv-audit-to-law --resource "$VAULT_ID" \
      --workspace "$LAW" --logs '[{"category":"AuditEvent","enabled":true}]'
    ```

    ```kusto
    AzureDiagnostics
    | where ResourceProvider == "MICROSOFT.KEYVAULT" and OperationName == "SecretGet"
    | extend SecretName = tostring(split(column_ifexists("id_s", ""), "/")[4])
    | extend IdentityType = column_ifexists("identity_claim_idtyp_s", "")
    | project TimeGenerated, OperationName, SecretName, IdentityType, ResultSignature, httpStatusCode_d
    | order by TimeGenerated desc
    ```

7. **Prove no secret is in the repository** — search every file and every commit for the real value, printing only counts:
   see [scripts/check_no_secret.sh](./scripts/check_no_secret.sh).

---

## ✅ What You Should See

```text
$ ./scripts/run.sh
  identity source : AzureCliCredential
  secret found    : yes, 32 characters
  secret value    : ******** (never printed or saved)
  RESULT : OK - no secret stored in this script or its folder
```

-   An identity with only **Key Vault Reader** can list secret names but reading a value fails with
    `(Forbidden) ... Action: 'Microsoft.KeyVault/vaults/secrets/getSecret/action' ... ForbiddenByRbac`.
-   Log Analytics shows a `SecretGet` row with result `OK` / `200` for each read.

Full evidence with screenshots: [Task 1](./PROOF/HVMC_KeyVault_Task1_Report.pdf) ·
[Task 2](./PROOF/AccessGuard_Health_KeyVault_Task2_Deliverable.pdf) · [Task 3](./PROOF/HVMC_KeyVault_Task3_Report.pdf)

---

## 💡 Pro Tips / Edge Cases (all learned the hard way)

-   **Roles add up.** An identity in two groups gets both roles. To test one role, make the identity a member of that group only.
-   **Changes are not instant.** Role assignments take a few minutes; *removing and re-adding* a service principal to a group
    took almost **two hours** to take effect because Azure caches group memberships.
-   **Check who you are before trusting a result:** `az account show --query user`. A new terminal tab silently used my admin
    login, and an old tab was still signed in as the app.
-   `az ad group member list` does **not** show service principals; check `servicePrincipals/{id}/memberOf` or the audit log.
-   Certificate sign-in for an app: use `az login --service-principal -u <client-id> --certificate <key+cert.pem> --tenant <tenant>`
    (`-p` is rejected with AADSTS7000215 in newer Azure CLI). Delete the combined file afterwards.
-   A **new diagnostic setting** can take several minutes to start and the first logs much longer to arrive; reads in the first
    ~20 minutes were never logged. Use `column_ifexists()` so a query works before the first event.
-   The caller type is in `identity_claim_idtyp_s` (`user` / `app`); `clientInfo_s` tells a Python SDK call from an Azure CLI command.
-   Never print, log or commit secret values. Soft delete and purge protection mean deleted secrets can be recovered.

---

## 📚 Learn More

-   [Azure Key Vault documentation](https://learn.microsoft.com/azure/key-vault/)
-   [Provide access to Key Vault with Azure RBAC](https://learn.microsoft.com/azure/key-vault/general/rbac-guide)
-   [Azure Key Vault logging](https://learn.microsoft.com/azure/key-vault/general/logging)
-   [azure-keyvault-secrets for Python](https://learn.microsoft.com/python/api/overview/azure/keyvault-secrets-readme)
-   [HashiCorp Vault](https://developer.hashicorp.com/vault) — my next phase, see [HASHICORP_VAULT_NEXT_PHASE.md](./HASHICORP_VAULT_NEXT_PHASE.md)

---

## 👤 Authored by: Sabitha S Karanavar

🗓️ Date: 2026-11-03 (updated 2026-11-10 with the real steps and results)  
🔁 Validated by: pending educator review
