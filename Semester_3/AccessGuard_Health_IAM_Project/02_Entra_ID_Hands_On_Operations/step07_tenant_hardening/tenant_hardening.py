"""
Step 7 - free Entra ID tenant hardening (risks R08 and R04). Entra ID Free, $0.

Part A  settings    (change HVMC-IAM-CHG-106): tighten the tenant-wide authorization policy
        - users cannot consent to apps (admins review app access instead)
        - users cannot register apps, create tenants or create security groups (IAM process does it)
        - only admins and the Guest Inviter role can invite guests
        - guests see only their own directory object
        - no email-verified self-service sign-up or self-service subscriptions
Part B  breakglass  (change HVMC-IAM-CHG-107): two cloud-only emergency-access Global Administrators
        - on the .onmicrosoft.com domain (no dependency on a custom domain or federation)
        - 40-character random passwords that never expire, written ONLY to a local 0600 file
        - removes the single point of failure: today the tenant has exactly one Global Administrator

Dry run by default: shows before -> after and changes nothing.
    python3 tenant_hardening.py                      # dry run, both parts
    python3 tenant_hardening.py --part settings --apply
    python3 tenant_hardening.py --part breakglass --apply
Evidence (before/after JSON) goes to evidence/, which stays out of the public repo.
"""
import argparse
import datetime as dt
import json
import os
import secrets
import string
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "step2_rbac_v2"))
from rbac_v2 import graph  # noqa: E402

EVID = os.path.join(HERE, "evidence")
SECRET_FILE = os.path.join(HERE, "SECRET_breakglass_credentials.txt")
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
RESTRICTED_GUEST = "2af84b1e-32c8-42b7-82bc-daa82404023b"   # "Guest access is restricted to their own directory objects"
GUEST_ROLE_NAMES = {"a0b1b346-4d3e-4e8b-98f8-753987be4970": "same as members",
                    "10dae51f-b6af-4016-8d66-8c2a99b929b3": "limited (default)",
                    RESTRICTED_GUEST: "restricted to own object"}
BREAK_GLASS = [("bg-admin-01", "Emergency Access 01 (break glass)"),
               ("bg-admin-02", "Emergency Access 02 (break glass)")]

TARGET = {
    "allowInvitesFrom": "adminsAndGuestInviters",
    "guestUserRoleId": RESTRICTED_GUEST,
    "allowEmailVerifiedUsersToJoinOrganization": False,
    "allowedToSignUpEmailBasedSubscriptions": False,
    "defaultUserRolePermissions": {
        "allowedToCreateApps": False,
        "allowedToCreateSecurityGroups": False,
        "allowedToCreateTenants": False,
        "permissionGrantPoliciesAssigned": [],      # = "Do not allow user consent"
    },
}


def save(name, data):
    os.makedirs(EVID, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(EVID, f"{stamp}_{name}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def auth_policy():
    p = graph("get", "/policies/authorizationPolicy")
    return p["value"][0] if "value" in p else p


def show(v):
    if isinstance(v, list):
        return "[] (no user consent)" if not v else ", ".join(x.split(".")[-1] for x in v)
    return GUEST_ROLE_NAMES.get(v, v) if isinstance(v, str) else str(v)


def part_settings(apply):
    print("\n=== Part A: tenant settings (HVMC-IAM-CHG-106) ===")
    before = auth_policy()
    rows, patch = [], {}
    for k, v in TARGET.items():
        if k == "defaultUserRolePermissions":
            cur = before.get(k, {})
            for k2, v2 in v.items():
                rows.append((f"defaultUserRolePermissions.{k2}", cur.get(k2), v2))
            if any(cur.get(k2) != v2 for k2, v2 in v.items()):
                patch[k] = v
        else:
            rows.append((k, before.get(k), v))
            if before.get(k) != v:
                patch[k] = v
    for name, cur, new in rows:
        mark = "  (no change)" if cur == new else ""
        print(f"  {name:58} {show(cur):45} -> {show(new)}{mark}")
    if not patch:
        print("  Nothing to change.")
        return True
    if not apply:
        print(f"  DRY RUN: {len(patch)} setting group(s) would change. Run with --part settings --apply")
        return True
    save("authorizationPolicy_before", before)
    try:
        graph("patch", "/policies/authorizationPolicy", patch)
    except RuntimeError as e:
        print(f"  FAILED: {e}")
        if "scope" in str(e).lower() or "Forbidden" in str(e) or "Authorization" in str(e):
            print("  The Azure CLI sign-in token is not allowed to change this policy. Use the portal steps in "
                  "PORTAL_STEPS.md (same settings, about 5 minutes).")
        return False
    after = auth_policy()
    save("authorizationPolicy_after", after)
    bad = [n for n, _, new in rows if (after.get(n) if "." not in n else after["defaultUserRolePermissions"].get(n.split(".")[1])) != new]
    print("  APPLIED." if not bad else f"  APPLIED, but these did not take: {bad}")
    return not bad


def strong_password(n=40):
    """40 random characters from a 76-symbol alphabet (~250 bits); always includes all 4 character classes."""
    alphabet = string.ascii_letters + string.digits + "!#%+-.:=?@^_~"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(n))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
                and any(not c.isalnum() for c in pw)):
            return pw


def global_admins():
    roles = graph("get", f"/directoryRoles?$filter=roleTemplateId eq '{GLOBAL_ADMIN}'")["value"]
    if not roles:
        return None, []
    members = graph("get", f"/directoryRoles/{roles[0]['id']}/members?$select=id,displayName,userPrincipalName")["value"]
    return roles[0]["id"], members


def part_breakglass(apply):
    print("\n=== Part B: emergency-access (break-glass) accounts (HVMC-IAM-CHG-107) ===")
    domain = next(d["name"] for d in graph("get", "/organization?$select=verifiedDomains")["value"][0]["verifiedDomains"]
                  if d["name"].endswith(".onmicrosoft.com"))
    role_id, admins = global_admins()
    print(f"  Global Administrators now: {len(admins)} -> " + ", ".join(a["displayName"] for a in admins))
    plan = []
    for nick, name in BREAK_GLASS:
        upn = f"{nick}@{domain}"
        existing = graph("get", f"/users?$filter=userPrincipalName eq '{upn}'&$select=id,displayName,accountEnabled")["value"]
        is_ga = existing and any(a["id"] == existing[0]["id"] for a in admins)
        plan.append((nick, name, upn, existing[0] if existing else None, is_ga))
        state = "exists" if existing else "will be created"
        print(f"  {upn:58} {state}; Global Administrator: {'yes' if is_ga else 'will be assigned'}")
    print("  Settings: cloud-only, no licence, password never expires, no SG-* groups or app access.")
    print("  Note: security defaults stay ON, so each account must register MFA at its first sign-in.")
    if not apply:
        print("  DRY RUN: nothing created. Run with --part breakglass --apply")
        return True

    creds, results = [], []
    for nick, name, upn, existing, is_ga in plan:
        if existing is None:
            pw = strong_password()
            user = graph("post", "/users", {
                "accountEnabled": True, "displayName": name, "mailNickname": nick, "userPrincipalName": upn,
                "usageLocation": "US", "jobTitle": "Emergency access account - do not use for daily work",
                "department": "Information Security", "passwordPolicies": "DisablePasswordExpiration",
                "passwordProfile": {"password": pw, "forceChangePasswordNextSignIn": False},
            })
            creds.append((upn, pw))
            existing = user
            results.append(f"created {upn}")
        if not is_ga:
            if role_id is None:
                raise RuntimeError("Global Administrator role not activated in this tenant")
            graph("post", f"/directoryRoles/{role_id}/members/$ref",
                  {"@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{existing['id']}"})
            results.append(f"Global Administrator assigned to {upn}")
    if creds:
        fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("HVMC EMERGENCY-ACCESS (BREAK-GLASS) ACCOUNTS - created "
                    f"{dt.datetime.now():%Y-%m-%d %H:%M}\n"
                    "1. Copy each account into your password manager OR print this page and seal it in an envelope.\n"
                    "2. Then DELETE this file (move to Trash and empty the Trash).\n"
                    "3. Never use these accounts for daily work. Test sign-in once per quarter.\n\n")
            for upn, pw in creds:
                f.write(f"{upn}\n{pw}\n\n")
    _, after = global_admins()
    save("breakglass_after", {"results": results, "global_admins": [a["userPrincipalName"] for a in after]})
    for r in results:
        print(f"  {r}")
    print(f"  Global Administrators now: {len(after)} -> " + ", ".join(a["displayName"] for a in after))
    if creds:
        print(f"  Passwords were NOT printed. They are in: {SECRET_FILE} (readable only by you).")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--part", choices=["settings", "breakglass", "all"], default="all")
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    print(f"HVMC Step 7 tenant hardening - {'APPLY' if a.apply else 'DRY RUN (no changes)'}")
    ok = True
    if a.part in ("settings", "all"):
        ok &= part_settings(a.apply)
    if a.part in ("breakglass", "all"):
        ok &= part_breakglass(a.apply)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
