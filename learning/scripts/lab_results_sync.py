"""AccessGuard Health - HVMC Lab Results Sync job (Key Vault Task 3).

Before Task 3 this script kept the AccessGuard API key in the code:
    ACCESSGUARD_API_KEY = "..."        # hardcoded secret - anyone with the file can read it

Now the API key is read at run time from Azure Key Vault. The script holds no secret:
  - DefaultAzureCredential finds an identity automatically (Azure CLI login on this Mac;
    a managed identity or the app's certificate in production), and
  - Azure RBAC on the vault decides whether that identity may read the secret.
Every read is recorded by the vault's diagnostic logs (SecretGet) in Log Analytics.

The value is never printed or written to disk. The call to the lab-results API is simulated (lab, no live API).

Usage:  python lab_results_sync.py [secret-name]
Env:    KEY_VAULT_URL   default https://hvmc-accessguard-kv.vault.azure.net
"""
import logging
import os
import sys
from datetime import datetime, timezone

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError, ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

VAULT_URL = os.environ.get("KEY_VAULT_URL", "https://hvmc-accessguard-kv.vault.azure.net")
SECRET_NAME = sys.argv[1] if len(sys.argv) > 1 else "accessguard-api-key"
API_URL = "https://lab-results.hvmc.example/api/v1/results"   # lab simulation, not a live service


class CredentialSource(logging.Handler):
    """Captures which credential DefaultAzureCredential used, so the output shows the script's identity source."""
    source = "unknown"

    def emit(self, record):
        msg = record.getMessage()
        if "acquired a token from" in msg:
            CredentialSource.source = msg.rsplit("from", 1)[-1].strip()


def main():
    log = logging.getLogger("azure.identity")
    log.setLevel(logging.INFO)
    log.addHandler(CredentialSource())
    log.propagate = False

    print(f"[{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC] AccessGuard Health - HVMC Lab Results Sync")
    print(f"  vault  : {VAULT_URL}")
    print(f"  secret : {SECRET_NAME}")

    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    client = SecretClient(vault_url=VAULT_URL, credential=credential)
    try:
        secret = client.get_secret(SECRET_NAME)
    except ClientAuthenticationError:
        sys.exit("  RESULT : no identity found - sign in first (az login) or run with a managed identity")
    except ResourceNotFoundError:
        sys.exit(f"  RESULT : secret '{SECRET_NAME}' does not exist in the vault")
    except HttpResponseError as e:
        if e.status_code == 403:
            sys.exit("  RESULT : 403 Forbidden - this identity has no Key Vault role that allows reading secret values")
        raise

    value = secret.value or ""
    print(f"  identity source : {CredentialSource.source}")
    print(f"  secret found    : yes, {len(value)} characters, version ...{secret.properties.version[-6:]}")
    print("  secret value    : ******** (never printed or saved)")
    # The key is only held in memory for the API call, then dropped.
    print(f"  lab-results API : would call {API_URL} with the key in the request header (lab simulation)")
    del value
    print("  RESULT : OK - no secret stored in this script or its folder")


if __name__ == "__main__":
    main()
