"""Export the RBAC v2 matrix (step2_rbac_v2/rbac_v2.py) to rbac_matrix.json for the PowerShell lifecycle tools.

The Python matrix stays the single source of truth; re-run this after any RBAC change:
    python3 export_rbac_matrix.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "step2_rbac_v2"))
from rbac_v2 import HELD, MATRIX, group_name  # noqa: E402

out = {
    "source": "step2_rbac_v2/rbac_v2.py (RBAC v2, HVMC-IAM-CHG-102)",
    "groups": {dept: sorted(group_name(dept, app, acc) for app, acc in apps.items()) for dept, apps in MATRIX.items()},
    "held": [f"{d} / {a} / {x}: {why}" for (d, a, x), why in HELD.items()],
}
with open(os.path.join(HERE, "rbac_matrix.json"), "w") as f:
    json.dump(out, f, indent=2)
print(f"wrote rbac_matrix.json: {len(out['groups'])} departments, {sum(map(len, out['groups'].values()))} groups")
