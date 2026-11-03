# Observability & Logging: Project Notes

This document tracks my progress and implementation of observability features for the Azure Key Vault integration in AccessGuard Health. The design below is my plan; I tick each box and replace sample output with real output only after I have built and verified it.

---

## 1. Health Check Endpoint

**Have you implemented a health-check endpoint?**  
(Replace `[ ]` with `[x]`)

-   [ ] Yes
-   [ ] No
-   [x] Not applicable to my project

AccessGuard Health is an IAM simulation and scripts project, not a running web service, so there is no HTTP endpoint. Instead, I plan a small **vault health-check script** that confirms the app can reach Key Vault and read a test secret.

**Your endpoint path:**  
Not applicable (script: `scripts/vault_health_check.py`, run from the command line)

```
# Planned sample output (replace with real output after running):
{
  "status": "ok",
  "vault": "<vault-name>",
  "secret_read": true,
  "checked_at": "YYYY-MM-DDTHH:MM:SSZ"
}
```

**Why is this useful?**

> It lets me confirm in one command that authentication, network access, and the RBAC role assignment for the app identity all work, before debugging anything else.

---

## 2. Health Check Test

**Did you write a test for the health-check endpoint?**

-   [ ] Yes
-   [ ] No

**Paste your test code or description here:**

```
# Planned test (Python + pytest); tick "Yes" after it passes
from scripts.vault_health_check import check_vault

def test_vault_health_ok():
    result = check_vault()
    assert result["status"] == "ok"
    assert result["secret_read"] is True

def test_vault_health_fails_without_access(monkeypatch):
    # simulate a wrong vault URL; the check should report failure, not crash
    monkeypatch.setenv("VAULT_URL", "https://does-not-exist.vault.azure.net")
    result = check_vault()
    assert result["status"] == "error"
```

---

## 3. Log Event or Metric

**Name of log event or metric:**  
`secret_retrieved` (application log) and `SecretGet` (Azure Key Vault audit log). I also plan to watch for `secret_access_denied` (Forbidden results).

**What triggers this?**  
Each time the AccessGuard Health script reads a secret from Key Vault (`SecretGet`). A denied attempt, such as the Key Vault Reader identity trying to read a secret value, produces a Forbidden result.

**Sample output format or log:**

```
# Planned application log (JSON; never log the secret value)
{
  "event": "secret_retrieved",
  "secret_name": "servicenow-lab-password",
  "identity": "<app-identity>",
  "timestamp": "YYYY-MM-DDTHH:MM:SSZ"
}
```

**Where is this implemented in your code?**  
Planned: `scripts/keyvault_client.py → get_secret()` for the application log. The `SecretGet` audit events come from Azure diagnostic settings on the vault (no code needed).

---

## 4. Optional Monitoring Tools

**Did you use monitoring tools (e.g. Grafana, Prometheus, Kibana)?**

-   [ ] Yes
-   [ ] No

**Tool name(s):**  
Planned: Azure Monitor with a Log Analytics workspace (Key Vault diagnostic setting, category `AuditEvent`).

**Screenshot or description of what the tool shows:**

```
# Planned query to show who accessed which secret:
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "SecretGet"
| project TimeGenerated, OperationName, ResultSignature, CallerIPAddress, identity_claim_appid_g
| order by TimeGenerated desc

# Description to confirm after running it:
Shows each secret read, whether it succeeded (OK) or was denied (Forbidden), and which identity made it.
```

---

## 5. Reflection & Learning

**What did you learn while implementing observability in your project?**

> Draft (edit to match what actually happened): Secrets management is not only about storing secrets safely; it is also about proving who accessed them. The Key Vault audit log gives Security the evidence it needs for access reviews without ever exposing secret values.

**Anything you would do differently or improve in the future?**

> Draft: Add alerts for repeated Forbidden attempts, rotate secrets on a schedule, and, in a later phase, add HashiCorp Vault for on-premises secrets (such as the Samba4 domain controller) and compare its audit logging with Key Vault's.

---
