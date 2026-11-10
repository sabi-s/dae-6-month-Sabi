#!/bin/bash
# Proof for Task 3: the real secret values are NOT anywhere in the repository (current branch or history).
# Each value is read from Key Vault into memory only, searched for with git, and never printed.
export PATH=~/.azure-cli-env/bin:$PATH; unset AZURE_CONFIG_DIR
REPO="${1:-$HOME/Desktop/dae 6month_Sabi}"; cd "$REPO" || exit 1
echo "Repository: $(basename "$REPO")   branch: $(git rev-parse --abbrev-ref HEAD)"
for s in accessguard-api-key servicenow-lab-password; do
  v=$(az keyvault secret show --vault-name hvmc-accessguard-kv -n "$s" --query value -o tsv)
  now=$(git grep -F -c -- "$v" | wc -l | tr -d ' ')
  hist=$(git log --all -S"$v" --oneline | wc -l | tr -d ' ')
  echo "  $s : files containing the value = $now   commits that ever added it = $hist"
  unset v
done
echo "Hardcoded-key patterns in learning/scripts:"
git grep -n -i -E "(api[_-]?key|password|secret) *= *['\"][^'\"]{8,}" -- learning/scripts || echo "  none found"
