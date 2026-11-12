"""pytest tests for vault_health_check.py (run: pytest -v learning/scripts/test_vault_health_check.py).
Needs a signed-in identity with a Key Vault data role (e.g. az login as the IAM admin)."""
import json
import logging

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
