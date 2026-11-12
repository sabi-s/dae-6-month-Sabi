# Observability & Logging: Project Notes

This document records the observability features of the Azure Key Vault integration in AccessGuard Health:
a health check, a test for it, an application log event, and the Key Vault audit log in Log Analytics.
**All sections are built and verified (last run 12 Nov 2026).**

---

## 1. Health Check Endpoint

**Have you implemented a health-check endpoint?**  
(Replace `[ ]` with `[x]`)

-   [x] Yes
-   [ ] No
-   [ ] Not applicable to my project

AccessGuard Health is an IAM simulation and scripts project, not a running web service, so the health check is a
**command-line health-check script** instead of an HTTP endpoint. In one command it confirms that authentication,
network access and the RBAC role assignment all work, by reading one secret. It prints a JSON result, writes a JSON log
event, and exits with code 0 (ok) or 1 (error). The secret value is never printed, logged or saved.

**Your endpoint path:**  
`learning/scripts/vault_health_check.py` (run: `python vault_health_check.py [secret-name]`; vault URL from `KEY_VAULT_URL`)

```
$ python vault_health_check.py
{
  "status": "ok",
  "vault": "hvmc-accessguard-kv",
  "secret": "accessguard-api-key",
  "secret_read": true,
  "identity_source": "AzureCliCredential",
  "checked_at": "2026-11-12T17:50:28Z"
}
exit code: 0

$ KEY_VAULT_URL=https://does-not-exist-hvmc-0000.vault.azure.net python vault_health_check.py
{
  "status": "error",
  "vault": "does-not-exist-hvmc-0000",
  "secret": "accessguard-api-key",
  "secret_read": false,
  "identity_source": null,
  "checked_at": "2026-11-12T17:50:29Z",
  "error": "vault not reachable (wrong URL or network)"
}
exit code: 1
```

The check also reports clear errors for "no identity available", "403 Forbidden — no Key Vault role allows reading this
secret" and "secret not found".

**Why is this useful?**

> It lets me confirm in one command that authentication, network access, and the RBAC role assignment for the identity all
> work, before debugging anything else. A scheduler or pipeline can use the exit code to alert when the vault is unreachable
> or a role has been removed.

---

## 2. Health Check Test

**Did you write a test for the health-check endpoint?**

-   [x] Yes
-   [ ] No

**Paste your test code or description here:**

`learning/scripts/test_vault_health_check.py` (pytest, 3 tests):

```python
from vault_health_check import check_vault

def test_vault_health_ok():
    result = check_vault()
    assert result["status"] == "ok"
    assert result["secret_read"] is True

def test_vault_health_fails_without_access(monkeypatch):
    # a vault that does not exist: the check must report an error, not crash
    monkeypatch.setenv("KEY_VAULT_URL", "https://does-not-exist-hvmc-0000.vault.azure.net")
    result = check_vault()
    assert result["status"] == "error"
    assert result["secret_read"] is False
    assert "error" in result

def test_log_event_never_contains_secret(caplog):
    caplog.set_level(logging.INFO, logger="accessguard.vault")
    check_vault()
    events = [json.loads(r.getMessage()) for r in caplog.records if r.name == "accessguard.vault"]
    assert events and events[-1]["event"] == "secret_retrieved"
    assert "value" not in events[-1]
```

Real result (12 Nov 2026):

```
$ pytest -v test_vault_health_check.py
test_vault_health_check.py::test_vault_health_ok PASSED                  [ 33%]
test_vault_health_check.py::test_vault_health_fails_without_access PASSED [ 66%]
test_vault_health_check.py::test_log_event_never_contains_secret PASSED  [100%]
============================== 3 passed in 1.06s ===============================
```

---

## 3. Log Event or Metric

**Name of log event or metric:**  
Two levels, both implemented and verified:

1. **Application log event** `secret_retrieved` / `secret_access_failed` — written by `vault_health_check.py` as one JSON line.
2. **Key Vault audit event** `SecretGet` — written by Azure for every secret read, sent to Log Analytics.

**What triggers this?**  
Each time the health check (or any identity) reads a secret from the vault. A failed attempt — wrong vault, missing identity
or a role without permission (for example the Key Vault Reader reading a value) — produces `secret_access_failed` in the
application log and a Forbidden result in the audit log.

**Sample output format or log:**

```
# Application log (stderr, JSON — never contains the secret value)
{"event": "secret_retrieved", "secret_name": "accessguard-api-key", "vault": "hvmc-accessguard-kv", "identity_source": "AzureCliCredential", "timestamp": "2026-11-12T17:50:28Z"}
{"event": "secret_access_failed", "secret_name": "accessguard-api-key", "vault": "does-not-exist-hvmc-0000", "identity_source": null, "timestamp": "2026-11-12T17:50:29Z", "error": "vault not reachable (wrong URL or network)"}

# Key Vault audit log in Log Analytics (10 Nov 2026)
TimeGenerated (UTC)   OperationName  SecretName           IdentityType  Client                               Result
2026-11-10 19:39:18   SecretGet      accessguard-api-key  user          lab_results_sync.py (Azure SDK)      OK 200
2026-11-10 19:39:17   SecretGet      accessguard-api-key  user          Azure CLI command (no-secret check)  OK 200
```

**Where is this implemented in your code?**  
- Application log: `learning/scripts/vault_health_check.py → check_vault()` (logger `accessguard.vault`). The Azure SDK's own
  request logging is turned down to WARNING so request dumps (which include the caller's IP address) are never printed.
- Audit log: vault diagnostic setting `kv-audit-to-law` (category `AuditEvent`) → Log Analytics workspace `HVMC-SecOps-LAW`.

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

Screenshot: Figure 2 of [PROOF/HVMC_KeyVault_Task3_Report.pdf](./PROOF/HVMC_KeyVault_Task3_Report.pdf).

---

## 5. Reflection & Learning

**What did you learn while implementing observability in your project?**

> Secrets management is not only about storing secrets safely; it is also about proving who accessed them. The audit log
> recorded every read — even my own admin checks. I also learned to read it critically: my first query labelled the caller
> "Application" when it was really a user, and the right fields were `identity_claim_idtyp_s` and `clientInfo_s`. A new
> diagnostic setting did not log reads in its first ~20 minutes. When I built the health check I found that the Azure SDK's
> default request logging prints the caller's IP address and tenant ID, so I turned it down — logging must not leak data either.

**Anything you would do differently or improve in the future?**

> Turn logging on before any secret is read; add alerts for unusual `SecretGet` activity and repeated Forbidden attempts;
> run the health check on a schedule; rotate secrets on a schedule; and, in the next phase, compare with HashiCorp Vault's
> audit device ([HASHICORP_VAULT_NEXT_PHASE.md](./HASHICORP_VAULT_NEXT_PHASE.md)).

---
