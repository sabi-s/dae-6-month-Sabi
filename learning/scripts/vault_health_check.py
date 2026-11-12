"""AccessGuard Health - Key Vault health check (observability, learning/NOTES.md sections 1-3).

Confirms in one command that the identity, the vault and the RBAC role all work, by reading one secret.
Prints a JSON result and writes one JSON log event (secret_retrieved / secret_access_failed).
The secret value is never printed, logged or saved.

Usage:  python vault_health_check.py [secret-name]
Env:    KEY_VAULT_URL   default https://hvmc-accessguard-kv.vault.azure.net
"""
import json
import logging
import os
import sys
from datetime import datetime, timezone

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceNotFoundError, ServiceRequestError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

DEFAULT_VAULT = "https://hvmc-accessguard-kv.vault.azure.net"
log = logging.getLogger("accessguard.vault")


class _CredentialSource(logging.Handler):
    """Remembers which credential DefaultAzureCredential used (e.g. AzureCliCredential)."""
    source = None

    def emit(self, record):
        msg = record.getMessage()
        if "acquired a token from" in msg:
            _CredentialSource.source = msg.rsplit("from", 1)[-1].strip()


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def check_vault(secret_name="accessguard-api-key", vault_url=None):
    """Return a dict: status ok/error, vault, secret_read, identity_source, checked_at (+ error on failure)."""
    vault_url = vault_url or os.environ.get("KEY_VAULT_URL", DEFAULT_VAULT)
    idlog = logging.getLogger("azure.identity"); idlog.setLevel(logging.INFO); idlog.propagate = False
    logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)
    if not any(isinstance(h, _CredentialSource) for h in idlog.handlers):
        idlog.addHandler(_CredentialSource())
    result = {"status": "error", "vault": vault_url.split("//")[-1].split(".")[0], "secret": secret_name,
              "secret_read": False, "identity_source": None, "checked_at": _now()}
    try:
        client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential(exclude_interactive_browser_credential=True),
                              retry_total=1)
        secret = client.get_secret(secret_name)
        ok = bool(secret.value)
        result.update(status="ok" if ok else "error", secret_read=ok)
    except ClientAuthenticationError:
        result["error"] = "no identity available (sign in with az login or use a managed identity)"
    except ResourceNotFoundError:
        result["error"] = f"secret '{secret_name}' not found"
    except HttpResponseError as e:
        result["error"] = "403 Forbidden - no Key Vault role allows reading this secret" if e.status_code == 403 else f"HTTP {e.status_code}"
    except ServiceRequestError:
        result["error"] = "vault not reachable (wrong URL or network)"
    result["identity_source"] = _CredentialSource.source
    event = {"event": "secret_retrieved" if result["status"] == "ok" else "secret_access_failed",
             "secret_name": secret_name, "vault": result["vault"], "identity_source": result["identity_source"],
             "timestamp": result["checked_at"], **({"error": result["error"]} if "error" in result else {})}
    log.info(json.dumps(event))        # application log event - never contains the secret value
    return result


if __name__ == "__main__":
    h = logging.StreamHandler(sys.stderr); h.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(h); log.setLevel(logging.INFO); log.propagate = False
    logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)  # no request/response dumps
    out = check_vault(*(sys.argv[1:2]))
    print(json.dumps(out, indent=2))
    sys.exit(0 if out["status"] == "ok" else 1)
