#!/bin/bash
# Run lab_results_sync.py with the Azure CLI login (DefaultAzureCredential -> AzureCliCredential).
export PATH=~/.azure-cli-env/bin:$PATH
unset AZURE_CONFIG_DIR
cd "$(dirname "$0")" && "${PYTHON:-.venv/bin/python}" lab_results_sync.py "$@"
