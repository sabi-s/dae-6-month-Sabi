# Observability & Logging: Project Notes

This document tracks observability for the Azure Key Vault integration in AccessGuard Health. **Updated 2026-11-10:** the audit logging (sections 3–4) is built and verified; the health-check script (sections 1–2) is still a plan and is marked as such.

---

## 1. Health Check Endpoint

**Have you implemented a health-check endpoint?**  
(Replace `[ ]` with `[x]`)

-   [ ] Yes
-   [ ] No
-   [x] Not applicable to my project

AccessGuard Health is an IAM simulation and scripts project, not a running web service, so there is no HTTP endpoint. A separate health-check script is **not built yet**; for now `scripts/lab_results_sync.py` acts as the check: it exits with a clear message for "no identity", "403 Forbidden" or "secret not found", and prints `RESULT : OK` when the vault, identity and role all work.

**Your endpoint path:**  
Not applicable (planned script: `scripts/vault_health_check.py`; current check: `scripts/run.sh`)

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
`SecretGet` (Azure Key Vault audit log) — **implemented and verified**. A JSON application log (`secret_retrieved`) is still a plan.

**What triggers this?**  
Each time any identity reads a secret value from the vault. A denied attempt (for example the Key Vault Reader trying to read a value) is recorded with a Forbidden result.

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

**Where is this implemented?**  
Vault diagnostic setting `kv-audit-to-law` (category `AuditEvent`) → Log Analytics workspace `HVMC-SecOps-LAW`. No code needed. Real result (10 Nov 2026):

```
TimeGenerated (UTC)   OperationName  SecretName           IdentityType  Client                               Result
2026-11-10 19:39:18   SecretGet      accessguard-api-key  user          lab_results_sync.py (Azure SDK)      OK 200
2026-11-10 19:39:17   SecretGet      accessguard-api-key  user          Azure CLI command (no-secret check)  OK 200
```

---

## 4. Optional Monitoring Tools

**Did you use monitoring tools (e.g. Grafana, Prometheus, Kibana)?**

-   [x] Yes
-   [ ] No

**Tool name(s):**  
Azure Monitor — Log Analytics workspace `HVMC-SecOps-LAW` (Key Vault diagnostic setting, category `AuditEvent`).

**Screenshot or description of what the tool shows:**

```
# Query used (leaves out the caller's e-mail and IP address):
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" and OperationName == "SecretGet"
| extend SecretName = tostring(split(column_ifexists("id_s", ""), "/")[4])
| extend IdentityType = column_ifexists("identity_claim_idtyp_s", "")
| extend ci = column_ifexists("clientInfo_s", "")
| extend Client = case(ci has "keyvault-secrets", "lab_results_sync.py (Azure SDK)", ci has "AZURECLI", "Azure CLI command", ci)
| project TimeGenerated, OperationName, SecretName, IdentityType, Client, ResultSignature, httpStatusCode_d
| order by TimeGenerated desc

# What it shows (verified): each secret read, its result (OK / Forbidden), whether a user or an app made it, and which client.
```

---

## 5. Reflection & Learning

**What did you learn while implementing observability in your project?**

> Secrets management is not only about storing secrets safely; it is also about proving who accessed them. The audit log recorded every read — even my own admin checks. I also learned to read it critically: my first query labelled the caller "Application" when it was really a user, and the right fields were `identity_claim_idtyp_s` and `clientInfo_s`. A new diagnostic setting did not log reads in its first ~20 minutes.

**Anything you would do differently or improve in the future?**

> Turn logging on before any secret is read; add alerts for unusual `SecretGet` activity and repeated Forbidden attempts; build the health-check script and a JSON application log; rotate secrets on a schedule; and, in the next phase, compare with HashiCorp Vault's audit device ([HASHICORP_VAULT_NEXT_PHASE.md](./HASHICORP_VAULT_NEXT_PHASE.md)).

---
