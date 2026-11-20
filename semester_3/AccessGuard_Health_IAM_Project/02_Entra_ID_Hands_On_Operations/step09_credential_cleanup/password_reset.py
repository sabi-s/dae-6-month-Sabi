"""HVMC-IAM-CHG-109 - reset the passwords of the staff accounts created from the bulk-create CSV.

Why: ~/Downloads/HVMC_Entra_Bulk_Create_Users.csv holds every initial password in plain text (one was shown on
screen in an earlier session). After the reset those old passwords stop working.
How:
  - each account in the CSV gets a new random password (not forced to change, so the list stays usable in the lab)
  - the new passwords are never printed; they go straight into a password-protected zip
  - the zip is tested, then the old plain-text CSV and the temporary file are deleted
  - accounts with an admin role are never touched (the script stops if one appears)

    python3 password_reset.py            # dry run: check the accounts, change nothing
    python3 password_reset.py --apply    # reset, zip, verify, delete the old CSV
Evidence (who was reset, when - no passwords) goes to evidence/, which stays out of the public repo.
"""
import argparse
import csv
import datetime as dt
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "step2_rbac_v2"))
from rbac_v2 import AZ, G, graph  # noqa: E402

OLD_CSV = os.path.expanduser("~/Downloads/HVMC_Entra_Bulk_Create_Users.csv")
ZIP_OUT = os.path.expanduser("~/Downloads/HVMC_Staff_Passwords.zip")
INNER = f"HVMC_Staff_Passwords_{dt.date.today().isoformat()}.csv"
EVID = os.path.join(HERE, "evidence")


def mask(upn):
    return upn.split("@")[0] + "@<tenant>"


def new_password(n=16):
    """16 characters, all four character classes (meets Entra ID complexity), no look-alike characters."""
    alphabet = "".join(c for c in string.ascii_letters + string.digits if c not in "O0Il1") + "!#%+=?@"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(n))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
                and any(not c.isalnum() for c in pw)):
            return pw


def zip_password():
    """Easy to type: four groups of four lowercase letters, e.g. abcd-efgh-ijkl-mnop."""
    return "-".join("".join(secrets.choice(string.ascii_lowercase) for _ in range(4)) for _ in range(4))


def set_password(user_id, pw, tmpdir):
    """PATCH the password; the body goes through a 0600 file so the password is not on the command line."""
    body = os.path.join(tmpdir, "body.json")
    fd = os.open(body, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"passwordProfile": {"password": pw, "forceChangePasswordNextSignIn": False}}, f)
    try:
        r = subprocess.run([AZ, "rest", "--method", "patch", "--url", f"{G}/users/{user_id}",
                            "--headers", "Content-Type=application/json", "--body", f"@{body}"],
                           capture_output=True, text=True)
    finally:
        os.remove(body)
    return r.returncode == 0, r.stderr.strip().splitlines()[-1] if r.returncode else ""


def admins():
    ids = set()
    for role in graph("get", "/directoryRoles?$select=id,displayName")["value"]:
        ids |= {m["id"] for m in graph("get", f"/directoryRoles/{role['id']}/members?$select=id")["value"]}
    return ids


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    apply = ap.parse_args().apply

    with open(OLD_CSV, newline="", encoding="utf-8-sig") as f:
        rows = [r for r in csv.reader(f)][1:]
    upns = [r[1].strip() for r in rows if len(r) > 1 and "@" in r[1]]
    print(f"HVMC-IAM-CHG-109  {'APPLY' if apply else 'DRY RUN'}  - {len(upns)} accounts in the bulk-create CSV")

    admin_ids = admins()
    found, missing = [], []
    for upn in upns:
        res = graph("get", f"/users?$filter=userPrincipalName eq '{upn}'"
                           "&$select=id,displayName,userPrincipalName,department,accountEnabled")["value"]
        (found.append(res[0]) if res else missing.append(upn))
    blocked = [u for u in found if u["id"] in admin_ids]
    if blocked:
        sys.exit("STOP: these CSV accounts hold an admin role, nothing changed: "
                 + ", ".join(mask(u["userPrincipalName"]) for u in blocked))

    enabled = [u for u in found if u["accountEnabled"]]
    disabled = [u for u in found if not u["accountEnabled"]]
    print(f"  found in Entra ID : {len(found)}  (enabled {len(enabled)}, disabled {len(disabled)})")
    for u in disabled:
        print(f"    disabled, reset anyway so the old password is dead if re-enabled: {u['displayName']}")
    for upn in missing:
        print(f"  not in the tenant (skipped): {mask(upn)}")
    print("  admin accounts in the CSV: 0  (your admin and bg-admin-01/02 are not in it)")

    if not apply:
        print(f"\n  DRY RUN: nothing changed. --apply resets {len(found)} passwords, writes {os.path.basename(ZIP_OUT)},")
        print("  tests it, then deletes the plain-text CSV.")
        return

    if os.path.exists(ZIP_OUT):
        sys.exit(f"STOP: {ZIP_OUT} already exists - move it away first.")
    tmpdir = tempfile.mkdtemp(prefix="chg109_")            # mode 0700
    inner = os.path.join(tmpdir, INNER)
    results = []
    fd = os.open(inner, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Name", "User name", "Password", "Department", "Account enabled", "Password set"])
        for u in found:
            pw = new_password()
            ok, err = set_password(u["id"], pw, tmpdir)
            if ok:
                w.writerow([u["displayName"], u["userPrincipalName"], pw, u.get("department") or "",
                            u["accountEnabled"], dt.datetime.now().strftime("%Y-%m-%d %H:%M")])
            results.append({"user": mask(u["userPrincipalName"]), "reset": ok, "error": err})
            print(f"  {'reset' if ok else 'FAILED':6}  {u['displayName']}{'  ' + err if err else ''}")
            f.flush()

    zpw = zip_password()
    subprocess.run(["zip", "-j", "-q", "-P", zpw, ZIP_OUT, inner], check=True)
    os.chmod(ZIP_OUT, 0o600)
    test = subprocess.run(["unzip", "-p", "-P", zpw, ZIP_OUT], capture_output=True, text=True)
    n_ok = sum(r["reset"] for r in results)
    zip_ok = test.returncode == 0 and len(list(csv.reader(test.stdout.splitlines()))) == n_ok + 1
    shutil.rmtree(tmpdir)

    os.makedirs(EVID, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(os.path.join(EVID, f"{stamp}_password_reset.json"), "w") as f:
        json.dump({"change": "HVMC-IAM-CHG-109", "time": stamp, "forceChangePasswordNextSignIn": False,
                   "reset_ok": n_ok, "failed": len(results) - n_ok, "zip_verified": zip_ok,
                   "old_csv_deleted": zip_ok and n_ok == len(results), "accounts": results}, f, indent=2)

    print(f"\n  {n_ok}/{len(results)} passwords reset (no forced change at next sign-in)")
    print(f"  zip test: {'OK - opens with the password and holds ' + str(n_ok) + ' rows' if zip_ok else 'FAILED'}")
    if zip_ok and n_ok == len(results):
        os.remove(OLD_CSV)
        print(f"  old plain-text CSV deleted: {OLD_CSV}")
    else:
        print("  old CSV KEPT because something failed - check above")
    print(f"\n  ZIP FILE     : {ZIP_OUT}")
    print(f"  ZIP PASSWORD : {zpw}     <- save this now (password manager or paper); it is shown only once")


if __name__ == "__main__":
    main()
